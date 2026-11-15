// Allow-list sanitizer for inbound HTML mail. The original HTML is kept unchanged (`untrustedHtml`); this produces a
// separate rendering a UI can show without executing anything or contacting a remote host. Structure and text survive;
// scripts, styles, event handlers, forms, frames, embedded objects and all images (remote images are tracking beacons,
// `cid:` images need attachment mapping) are removed; links keep only http, https and mailto targets.
import sanitizeHtml from 'sanitize-html';

export const HTML_SANITIZER = 'sanitize-html@2.18.1 allow-list v1';
const MAX_INPUT = 1_000_000;

const OPTIONS: sanitizeHtml.IOptions = {
  allowedTags: ['p', 'br', 'div', 'span', 'b', 'strong', 'i', 'em', 'u', 's', 'small', 'sub', 'sup', 'mark', 'blockquote', 'q', 'cite', 'pre', 'code',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'abbr', 'a',
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption'],
  allowedAttributes: { a: ['href', 'title', 'rel'], abbr: ['title'], ol: ['start'], td: ['colspan', 'rowspan'], th: ['colspan', 'rowspan'] },
  allowedSchemes: ['http', 'https', 'mailto'],
  allowedSchemesAppliedToAttributes: ['href'],
  allowProtocolRelative: false,
  disallowedTagsMode: 'discard',
  nonTextTags: ['script', 'style', 'textarea', 'option', 'noscript', 'title', 'head', 'template', 'svg', 'math', 'iframe', 'object', 'xmp', 'noembed', 'noframes'],
  transformTags: { a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer nofollow' }, true) },
  enforceHtmlBoundary: false,
  parseStyleAttributes: false,
};

/** Returns markup containing only allow-listed elements and attributes. Never throws on hostile input. */
export function sanitizeInboundHtml(html: string | null | undefined): string | null {
  if (typeof html !== 'string') return null;
  try { return sanitizeHtml(html.slice(0, MAX_INPUT).replace(/\u0000/g, ''), OPTIONS); } catch { return ''; }
}
