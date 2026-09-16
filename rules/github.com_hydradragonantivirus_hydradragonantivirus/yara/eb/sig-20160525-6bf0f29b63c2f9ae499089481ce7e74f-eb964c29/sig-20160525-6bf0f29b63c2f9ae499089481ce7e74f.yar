rule sig_20160525_6bf0f29b63c2f9ae499089481ce7e74f {
  meta:
    description = "datamaliciousorder - file 20160525_6bf0f29b63c2f9ae499089481ce7e74f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eebe15682b2341b662b6e5acd0632c013b0ae1e193d6e587995a9961ac39bb8"

  strings:
    $s1  = "43 + Math.round((Math.pow(Math.sin(393), 2) + Math.pow(Math.cos(393), 2) - 1))-779)) mmcbFjhRKwTMFITwS += xB(jIJdZ);else if (ntA" ascii
    $s2  = "function bGnHX(mKFQdEXjEUiUv) {var RqIfBcbBtVAwINywcrtKSsfc = AoydEmSymrsalfrU.join(oWlWwEhDRvFjeRHH[0]);var jIJdZ, QlGFUgHUNztr" ascii
    $s3  = "function lgkduqGrs(nzTTcHhJBTTosAa,GgtEJspbHhbfYsSn){return nzTTcHhJBTTosAa.charAt(GgtEJspbHhbfYsSn);}" fullword ascii
    $s4  = "function xB(fCnxpsZ){return String.fromCharCode(fCnxpsZ);}" fullword ascii
    $s5  = "RtSUoXrnYzMwllaRaK);} while (KCHsBEUedMYeadgrpJ < mKFQdEXjEUiUv.length);return mmcbFjhRKwTMFITwS;}" fullword ascii
    $s6  = "function xQQkSUnbpCqHWhOQDGwqAj(RlsCNbtpMUxgnEmENYd,TfXttLSx,REKDD){return String.fromCharCode(RlsCNbtpMUxgnEmENYd,TfXttLSx,REKD" ascii
    $s7  = "function xQQkSUnbpCqHWhOQDGwqAj(RlsCNbtpMUxgnEmENYd,TfXttLSx,REKDD){return String.fromCharCode(RlsCNbtpMUxgnEmENYd,TfXttLSx,REKD" ascii
    $s8  = "function bGnHX(mKFQdEXjEUiUv) {var RqIfBcbBtVAwINywcrtKSsfc = AoydEmSymrsalfrU.join(oWlWwEhDRvFjeRHH[0]);var jIJdZ, QlGFUgHUNztr" ascii
    $s9  = "function iVgYtKshxvCRFZX(YcYQtdEWfw,bfoBhqdDmVvebD){return String.fromCharCode(YcYQtdEWfw,bfoBhqdDmVvebD);}" fullword ascii
    $s10 = "+= iVgYtKshxvCRFZX(jIJdZ, QlGFUgHUNztrJCOVEgC);else mmcbFjhRKwTMFITwS += xQQkSUnbpCqHWhOQDGwqAj(jIJdZ, QlGFUgHUNztrJCOVEgC, SkkP" ascii
    $s11 = "function BbUXOQYWp(YbyNEcJTJVHPODHkKmG,sjCtdpXptywcimzCtf){return YbyNEcJTJVHPODHkKmG.indexOf(sjCtdpXptywcimzCtf);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}