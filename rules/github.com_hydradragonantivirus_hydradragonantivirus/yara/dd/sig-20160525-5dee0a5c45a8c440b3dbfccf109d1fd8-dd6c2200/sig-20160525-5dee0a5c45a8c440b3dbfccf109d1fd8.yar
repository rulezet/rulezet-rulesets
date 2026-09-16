rule sig_20160525_5dee0a5c45a8c440b3dbfccf109d1fd8 {
  meta:
    description = "datamaliciousorder - file 20160525_5dee0a5c45a8c440b3dbfccf109d1fd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4200fcf70ce8534232fffab8854d1fc167290e60ca63dc414cb505a6b0ce40a9"

  strings:
    $s1  = "ath.sin(629), 2) + Math.pow(Math.cos(629), 2) - 1))-709)) rvIvFJiNuUcuB += kM(CdOSVaWJoR);else if (nryTnYtmbVODkbjTigkOlLmL == (" ascii
    $s2  = "function HRksn(GKqVTSSvgBPXY) {var rSxYoQQNlbbgHa = rvJVsmDnTuk.join(yHerKGxeeuyojza[0]);var CdOSVaWJoR, LtlBp, slfiAMEFLEgQMf, " ascii
    $s3  = "function ASjAftUeDpeVPtZyMwqpgp(NQhnyjZPVjKIsi,wPkvOISsOxbdgWib){return NQhnyjZPVjKIsi.charAt(wPkvOISsOxbdgWib);}" fullword ascii
    $s4  = "function rUzutnUSCzYaBfouBBqELN(fURjN,OfgEoDaVS){return fURjN.indexOf(OfgEoDaVS);}" fullword ascii
    $s5  = "function ddmmOsVVSIpoaVPghIaUR(ONTAqguToDMORnl,NdNEsddOXIidNyueSbFmjA){return String.fromCharCode(ONTAqguToDMORnl,NdNEsddOXIidNy" ascii
    $s6  = "VaWJoR, LtlBp);else rvIvFJiNuUcuB += TlnHOIFbeQtPAyqTJgoV(CdOSVaWJoR, LtlBp, slfiAMEFLEgQMf);} while (ayxxJISnu < GKqVTSSvgBPXY." ascii
    $s7  = "function TlnHOIFbeQtPAyqTJgoV(ZuGfaVqJOxLhAKmvkXK,fgzZJXDaCbgUIcJkCyRWBzn,VCmTrjvKFWqWiqCgkb){return String.fromCharCode(ZuGfaVq" ascii
    $s8  = "function TlnHOIFbeQtPAyqTJgoV(ZuGfaVqJOxLhAKmvkXK,fgzZJXDaCbgUIcJkCyRWBzn,VCmTrjvKFWqWiqCgkb){return String.fromCharCode(ZuGfaVq" ascii
    $s9  = "function kM(xUwbJDmlKaUXLERSIUJiFf){return String.fromCharCode(xUwbJDmlKaUXLERSIUJiFf);}" fullword ascii
    $s10 = "function HRksn(GKqVTSSvgBPXY) {var rSxYoQQNlbbgHa = rvJVsmDnTuk.join(yHerKGxeeuyojza[0]);var CdOSVaWJoR, LtlBp, slfiAMEFLEgQMf, " ascii
    $s11 = "function ddmmOsVVSIpoaVPghIaUR(ONTAqguToDMORnl,NdNEsddOXIidNyueSbFmjA){return String.fromCharCode(ONTAqguToDMORnl,NdNEsddOXIidNy" ascii
    $s12 = "length);return rvIvFJiNuUcuB;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}