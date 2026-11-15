// Inbound HTML sanitizer: hostile markup is reduced to inert, allow-listed structure; nothing can run or fetch.
import assert from 'node:assert/strict';
import test from 'node:test';
import { sanitizeInboundHtml } from '../src/engine/html.ts';

const s = (html: string): string => sanitizeInboundHtml(html) as string;

test('scripts, styles, handlers, frames, forms and embedded content are removed with their content', () => {
  const out = s(`<p onclick="steal()">Ledger <b>B</b></p><script>alert(1)</script><style>p{background:url(https://t.invalid/x)}</style>
    <iframe src="https://evil.invalid"></iframe><object data="x.swf"></object><embed src="x"><form action="https://evil.invalid"><input name="pw"><button>Go</button></form>
    <svg onload="alert(1)"><script>alert(2)</script></svg><math><mi>x</mi></math><template><img src=x onerror=alert(3)></template><noscript>ns</noscript><!-- comment -->`);
  assert.equal(out.replace(/\s+/g, ' ').trim(), '<p>Ledger <b>B</b></p> Go');
  for (const bad of ['script', 'style', 'iframe', 'object', 'embed', 'form', 'input', 'svg', 'math', 'onclick', 'onload', 'onerror', 'alert', 'evil.invalid', 'comment']) assert.ok(!out.includes(bad), bad);
});

test('links keep only http, https and mailto targets and are marked nofollow/noopener; images never load', () => {
  const out = s(`<a href="javascript:alert(1)">a</a><a href="JaVaScRiPt&#58;alert(1)">b</a><a href="&#x6A;avascript:alert(1)">c</a><a href=" java\tscript:alert(1)">d</a>
    <a href="data:text/html;base64,PHNjcmlwdD4=">e</a><a href="vbscript:x">f</a><a href="//proto.invalid/x">g</a><a href="https://records.example.org/page?x=1" target="_top" style="x" id="i">h</a><a href="mailto:clerk@example.net">i</a>
    <img src="https://tracker.invalid/pixel.gif"><img src="cid:part1"><img src="data:image/png;base64,AAAA"><picture><source srcset="https://tracker.invalid/a.png"></picture>
    <div style="background:url(https://tracker.invalid/b)" class="c" background="https://tracker.invalid/c">body</div><table background="https://tracker.invalid/d"><tr><td colspan="2" onmouseover="x">cell</td></tr></table>`);
  assert.ok(!/javascript|vbscript|data:|proto\.invalid|tracker\.invalid|cid:|<img|style=|class=|target=|id=|onmouseover/i.test(out), out);
  assert.match(out, /<a href="https:\/\/records\.example\.org\/page\?x=1" rel="noopener noreferrer nofollow">h<\/a>/);
  assert.match(out, /<a href="mailto:clerk@example\.net" rel="noopener noreferrer nofollow">i<\/a>/);
  assert.match(out, /<td colspan="2">cell<\/td>/);
  assert.match(out, /<div>body<\/div>/);
});

test('text is escaped, structure kept, malformed and oversized input handled', () => {
  assert.equal(s('<p>5 &lt; 6 &amp; "quoted" <unknown>tag</unknown></p>'), '<p>5 &lt; 6 &amp; "quoted" tag</p>');
  assert.equal(s('<blockquote><p>On Monday the clerk wrote:</p><ul><li>one</li></ul></blockquote>'), '<blockquote><p>On Monday the clerk wrote:</p><ul><li>one</li></ul></blockquote>');
  assert.equal(s('<p>unclosed <b>bold'), '<p>unclosed <b>bold</b></p>');
  for (const nested of ['<<script>script>alert(1)<</script>/script>', '<scr<script>ipt>alert(1)</script>', '<a href="x"<script>alert(1)</script>']) assert.ok(!/<script|alert\(1\)<\/script>/i.test(s(nested)), nested);
  assert.ok(!s('<scr\u0000ipt>alert(1)</scr\u0000ipt>').includes('<script'));
  assert.equal(sanitizeInboundHtml(null), null);
  const big = s(`<p>${'x'.repeat(2_000_000)}</p>`);
  assert.ok(big.length <= 1_000_010);
  const deep = s('<div>'.repeat(20_000) + 'deep' + '</div>'.repeat(20_000));
  assert.ok(deep.includes('deep'));
});
