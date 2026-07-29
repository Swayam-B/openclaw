// Mattermost plugin module owns draft-preview final delivery.
import {
  createChannelPartialDeliveryError,
  isChannelPartialDeliveryError,
} from "openclaw/plugin-sdk/channel-inbound";
import {
  createMessageReceiptFromOutboundResults,
  defineFinalizableLivePreviewAdapter,
  deliverWithFinalizableLivePreviewAdapter,
  listMessageReceiptPlatformIds,
  type MessageReceipt,
} from "openclaw/plugin-sdk/channel-outbound";
import {
  buildTtsSupplementMediaPayload,
  getReplyPayloadTtsSupplement,
  isReasoningReplyPayload,
} from "openclaw/plugin-sdk/reply-payload";
import { updateMattermostPost, type MattermostClient, type MattermostPost } from "./client.js";
import { createMattermostDraftStream } from "./draft-stream.js";
import { canFinalizeMattermostPreviewInPlace } from "./monitor-context.js";
import type { MattermostReplyDeliveryResult } from "./reply-delivery.js";
import type { ChatType, ReplyPayload } from "./runtime-api.js";

export type MattermostDraftPreviewState = {
  /** True once the preview is the durable final post and must not be reused as a draft. */
  finalizedViaPreviewPost: boolean;
};

type MattermostDraftPreviewDeliverParams = {
  payload: ReplyPayload;
  info: { kind: "tool" | "block" | "final" };
  kind: ChatType;
  client: MattermostClient;
  draftStream: Pick<
    ReturnType<typeof createMattermostDraftStream>,
    "flush" | "postId" | "clear" | "discardPending" | "seal"
  >;
  effectiveReplyToId?: string;
  resolvePreviewFinalText: (text?: string) => string | undefined;
  previewState: MattermostDraftPreviewState;
  logVerboseMessage: (message: string) => void;
  deliverPayload: (payload: ReplyPayload) => Promise<MattermostReplyDeliveryResult>;
  // Visible same-thread finals can be delivered by editing the draft preview in
  // place (onPreviewFinalized) without ever calling deliverPayload; this lets the
  // caller record thread participation on that path too.
  recordThreadParticipation?: () => void;
};

export async function deliverMattermostReplyWithDraftPreview(
  params: MattermostDraftPreviewDeliverParams,
): Promise<MattermostReplyDeliveryResult> {
  if (isReasoningReplyPayload(params.payload)) {
    return {
      outcome: "reasoning_skipped",
      visibleReplySent: false,
      suppression: { reason: "no_visible_result" },
    };
  }

  let normalDeliveryResult: MattermostReplyDeliveryResult | undefined;
  let supplementalDeliveryResult: MattermostReplyDeliveryResult | undefined;
  let previewDeliveryResult: MattermostReplyDeliveryResult | undefined;
  let pendingPreviewFinalContent: string | undefined;
  let finalizedPreviewPost: MattermostPost | undefined;
  try {
    const finalization = await deliverWithFinalizableLivePreviewAdapter({
      kind: params.info.kind,
      payload: params.payload,
      adapter: defineFinalizableLivePreviewAdapter<ReplyPayload, string, { message: string }>({
        // Once the preview is finalized, later payloads must use durable sends.
        // Reusing the sealed draft would clear and delete the successful final post.
        ...(params.previewState.finalizedViaPreviewPost
          ? {}
          : {
              draft: {
                flush: params.draftStream.flush,
                clear: params.draftStream.clear,
                discardPending: params.draftStream.discardPending,
                seal: params.draftStream.seal,
                id: params.draftStream.postId,
              },
            }),
        buildFinalEdit: (payload) => {
          const hasMedia = Boolean(payload.mediaUrl) || (payload.mediaUrls?.length ?? 0) > 0;
          const ttsSupplement = getReplyPayloadTtsSupplement(payload);
          const previewFinalText = params.resolvePreviewFinalText(
            payload.text ?? ttsSupplement?.spokenText,
          );

          if (
            (hasMedia && !ttsSupplement) ||
            typeof previewFinalText !== "string" ||
            payload.isError ||
            !canFinalizeMattermostPreviewInPlace({
              kind: params.kind,
              previewRootId: params.effectiveReplyToId,
              threadRootId: params.effectiveReplyToId,
              replyToId: payload.replyToId,
            })
          ) {
            return undefined;
          }
          pendingPreviewFinalContent = previewFinalText;
          return { message: previewFinalText };
        },
        editFinal: async (previewPostId, edit) => {
          finalizedPreviewPost = await updateMattermostPost(params.client, previewPostId, edit);
        },
        resolveFinalizedId: (previewPostId) => finalizedPreviewPost?.id ?? previewPostId,
        onPreviewFinalized: (_previewPostId, receipt) => {
          params.previewState.finalizedViaPreviewPost = true;
          previewDeliveryResult = {
            outcome: "text",
            messageIds: listMessageReceiptPlatformIds(receipt),
            receipt,
            visibleReplySent: true,
            content: finalizedPreviewPost?.message ?? pendingPreviewFinalContent ?? "",
          };
          // The visible final reply landed by editing the preview post, so the normal
          // deliverPayload record path is skipped; record participation explicitly here.
          params.recordThreadParticipation?.();
        },
        buildSupplementalPayload: (payload) =>
          getReplyPayloadTtsSupplement(payload)
            ? buildTtsSupplementMediaPayload(payload)
            : undefined,
        deliverSupplemental: async (payload) => {
          supplementalDeliveryResult = await params.deliverPayload(payload);
          return supplementalDeliveryResult.visibleReplySent;
        },
        logPreviewEditFailure: (err) => {
          params.logVerboseMessage(
            `mattermost preview final edit failed; falling back to normal send (${String(err)})`,
          );
        },
      }),
      deliverNormally: async (payload) => {
        const supplement = getReplyPayloadTtsSupplement(payload);
        normalDeliveryResult = await params.deliverPayload(
          supplement && !payload.text?.trim() && supplement.visibleTextAlreadyDelivered !== true
            ? { ...payload, text: supplement.spokenText }
            : payload,
        );
        return normalDeliveryResult.visibleReplySent;
      },
    });

    if (finalization.kind !== "preview-finalized" || !previewDeliveryResult?.receipt) {
      return (
        normalDeliveryResult ?? {
          outcome: "empty",
          visibleReplySent: false,
          suppression: { reason: "no_visible_result" },
        }
      );
    }
    const receipt = createMessageReceiptFromOutboundResults({
      results: [
        { receipt: previewDeliveryResult.receipt },
        ...(supplementalDeliveryResult?.receipt
          ? [{ receipt: supplementalDeliveryResult.receipt }]
          : []),
      ],
    });
    return {
      outcome: supplementalDeliveryResult?.outcome === "media" ? "media" : "text",
      messageIds: listMessageReceiptPlatformIds(receipt),
      receipt,
      visibleReplySent: true,
      content: previewDeliveryResult.content,
    };
  } catch (error: unknown) {
    // A provider send can complete before preview cleanup fails. Preserve every
    // completed visible receipt so core cannot mistake that post-send failure for a safe retry.
    const completedVisibleResults: MattermostReplyDeliveryResult[] = [];
    const completedReceiptResults: Array<{ receipt: MessageReceipt } | { messageId: string }> = [];
    for (const result of [
      previewDeliveryResult,
      normalDeliveryResult,
      supplementalDeliveryResult,
    ]) {
      if (result?.visibleReplySent !== true) {
        continue;
      }
      completedVisibleResults.push(result);
      if (result.receipt) {
        completedReceiptResults.push({ receipt: result.receipt });
      } else {
        completedReceiptResults.push(
          ...(result.messageIds ?? []).map((messageId) => ({ messageId })),
        );
      }
    }
    if (completedVisibleResults.length === 0) {
      throw error;
    }
    const failedPartial = isChannelPartialDeliveryError(error) ? error.deliveryResult : undefined;
    const receipt = createMessageReceiptFromOutboundResults({
      results: [
        ...completedReceiptResults,
        ...(failedPartial?.receipt
          ? [{ receipt: failedPartial.receipt }]
          : (failedPartial?.messageIds ?? []).map((messageId) => ({ messageId }))),
      ],
    });
    throw createChannelPartialDeliveryError(error, {
      messageIds: listMessageReceiptPlatformIds(receipt),
      receipt,
      visibleReplySent: true,
      content:
        previewDeliveryResult?.content ??
        normalDeliveryResult?.content ??
        supplementalDeliveryResult?.content ??
        "",
    });
  }
}
