rule sig_20160811_1c83765e14db92fd7b7ab6a9f773204c {
  meta:
    description = "datamaliciousorder - file 20160811_1c83765e14db92fd7b7ab6a9f773204c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8573113569692fbc982be20c1c2036a565e15cad91edbfc1e9bfecd0beaf5af1"

  strings:
    $x1  = "var m47 = new Array(); function b81(s90) { return s90; }; function e84(w97,f52) { m47[f52] = w97; }; e84(b81('=1;n<'),147); func" ascii
    $s2  = "on x49(w97,f52) { m47[f52] = w97; }; x49(b81('Run(\"%'),758); function l16(w97,f52) { m47[f52] = w97; }; l16(b81(' /c R'),695); " ascii
    $s3  = " function k64(w97,f52) { m47[f52] = w97; }; k64(b81('\"mill'),44); function q20(w97,f52) { m47[f52] = w97; }; q20(b81('c.com\"')" ascii
    $s4  = "('.com'),52); function j91(w97,f52) { m47[f52] = w97; }; j91(b81('.c'),461); function d55(w97,f52) { m47[f52] = w97; }; d55(b81(" ascii
    $s5  = "789); function a19(w97,f52) { m47[f52] = w97; }; a19(b81('.com'),42); function r52(w97,f52) { m47[f52] = w97; }; r52(b81('CR\"+'" ascii
    $s6  = "}; i56(b81('fp'),897); function j11(w97,f52) { m47[f52] = w97; }; j11(b81('  - '),671); function k39(w97,f52) { m47[f52] = w97; " ascii
    $s7  = "52) { m47[f52] = w97; }; j43(b81(' /t RE'),782); function y45(w97,f52) { m47[f52] = w97; }; y45(b81('+cs'),700); function r41(w9" ascii
    $s8  = "('n+'),222); function z64(w97,f52) { m47[f52] = w97; }; z64(b81(' - '),595); function t80(w97,f52) { m47[f52] = w97; }; t80(b81(" ascii
    $s9  = "}; g24(b81('% /c '),903); function w83(w97,f52) { m47[f52] = w97; }; w83(b81('File'),245); function j81(w97,f52) { m47[f52] = w9" ascii
    $s10 = " w97; }; o19(b81('; '),847); function f17(w97,f52) { m47[f52] = w97; }; f17(b81(' - It'),628); function w80(w97,f52) { m47[f52] " ascii
    $s11 = "97,f52) { m47[f52] = w97; }; q48(b81('RYPT.t'),843); function b62(w97,f52) { m47[f52] = w97; }; b62(b81('e /t R'),748); function" ascii
    $s12 = "[f52] = w97; }; u37(b81('en'),58); function a27(w97,f52) { m47[f52] = w97; }; a27(b81('  - Yo'),650); function w30(w97,f52) { m4" ascii
    $s13 = "77); function t62(w97,f52) { m47[f52] = w97; }; t62(b81('C% /c '),914); function t78(w97,f52) { m47[f52] = w97; }; t78(b81('cs')" ascii
    $s14 = "m47[f52] = w97; }; c31(b81('+\".exe'),854); function r35(w97,f52) { m47[f52] = w97; }; r35(b81('ne'),317); function g46(w97,f52)" ascii
    $s15 = "1('ite'),668); function i24(w97,f52) { m47[f52] = w97; }; i24(b81('%TEMP'),92); function s22(w97,f52) { m47[f52] = w97; }; s22(b" ascii
    $s16 = "{ m47[f52] = w97; }; t96(b81('+\".txt'),792); function e37(w97,f52) { m47[f52] = w97; }; e37(b81('34)'),20); function e62(w97,f5" ascii
    $s17 = "unction r36(w97,f52) { m47[f52] = w97; }; r36(b81('\".txt\"'),831); function w24(w97,f52) { m47[f52] = w97; }; w24(b81('un('),79" ascii
    $s18 = "tion v46(w97,f52) { m47[f52] = w97; }; v46(b81('.exe\",'),237); function k63(w97,f52) { m47[f52] = w97; }; k63(b81('=4){'),242);" ascii
    $s19 = "nction c28(w97,f52) { m47[f52] = w97; }; c28(b81('s, da'),325); function q99(w97,f52) { m47[f52] = w97; }; q99(b81('\".exe\"'),2" ascii
    $s20 = "r86(w97,f52) { m47[f52] = w97; }; r86(b81('\".txt\"'),730); function e32(w97,f52) { m47[f52] = w97; }; e32(b81('rea'),267); func" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}