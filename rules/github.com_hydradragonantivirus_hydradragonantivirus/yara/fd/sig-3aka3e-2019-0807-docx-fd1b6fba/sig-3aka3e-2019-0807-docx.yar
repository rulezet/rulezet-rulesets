rule sig_3aka3e_2019_0807_docx {
  meta:
    description = "datamaliciousorder - file 3aka3e.2019-0807.docx.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae771418cdcba682dd1beafa62d6a6a2505b74748bbb61ed4b666332cafa3527"

  strings:
    $s1  = "function l()" fullword ascii
    $s2  = "function h()" fullword ascii
    $s3  = "function k()" fullword ascii
    $s4  = "function jQX(ea, b)" fullword ascii
    $s5  = "function kKP(Oey)" fullword ascii
    $s6  = "function cN(N)" fullword ascii
    $s7  = "function Ph()" fullword ascii
    $s8  = "function q(fVy)" fullword ascii
    $s9  = "function gT()" fullword ascii
    $s10 = "function exc()" fullword ascii
    $s11 = "function C(u, Flg)" fullword ascii
    $s12 = "function T(gR)" fullword ascii
    $s13 = "function ip(ToM, Qg)" fullword ascii
    $s14 = "function VV(Qk)" fullword ascii
    $s15 = "function M(iP, OMY, Ufk)" fullword ascii
    $s16 = "while (q(43) > 0)" fullword ascii
    $s17 = "function JK()" fullword ascii
    $s18 = "function qBE(aDt)" fullword ascii
    $s19 = "function R(K)" fullword ascii
    $s20 = "function xHW()" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    8 of them
}