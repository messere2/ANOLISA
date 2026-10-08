/**
 * Code-point-safe display truncation.
 *
 * String.prototype.slice counts UTF-16 code units, so a cut landing
 * inside a surrogate pair leaves a lone high surrogate that browsers
 * render as U+FFFD. Chat content regularly carries astral-plane
 * characters (emoji, CJK extensions), so every content-bearing clip in
 * the dashboard goes through this helper instead (#6738; the retained
 * output cap had the same class of bug on the byte boundary, #6539).
 */

/** Ellipsis appended by {@link truncateText} when the text is cut. */
const ELLIPSIS = '\u2026';

/**
 * Cut `text` to at most `max` Unicode code points, appending an ellipsis
 * when anything was removed. Astral-plane characters count as one point
 * each, and the cut always lands on a code-point boundary, so the
 * result is well-formed even when the clip passes through an emoji.
 */
export function truncateText(text: string, max: number): string {
  // Fast path: at most `max` code units implies at most `max` code points.
  if (text.length <= max) return text;
  let end = 0;
  let points = 0;
  while (end < text.length && points < max) {
    end += text.codePointAt(end)! > 0xffff ? 2 : 1;
    points += 1;
  }
  if (end >= text.length) return text;
  return text.slice(0, end) + ELLIPSIS;
}
