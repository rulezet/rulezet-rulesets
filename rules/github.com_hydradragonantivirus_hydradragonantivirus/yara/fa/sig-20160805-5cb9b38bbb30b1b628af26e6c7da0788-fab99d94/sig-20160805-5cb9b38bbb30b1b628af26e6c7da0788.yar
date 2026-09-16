rule sig_20160805_5cb9b38bbb30b1b628af26e6c7da0788 {
  meta:
    description = "datamaliciousorder - file 20160805_5cb9b38bbb30b1b628af26e6c7da0788.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be7fa0a5b22e26cdb62635b54ae16ae3e9da81285c7b6032e0e4b85e3e87eee4"

  strings:
    $x1  = "var y74 = new Array(); function s74(l85) { return l85; }; y74[639] = s74('t`s ', 22, 62); function k12(b41) { return b41; }; y74" ascii
    $s2  = "'i.com\"', 65, 86); function h15(k33) { return k33; }; y74[1] = h15(' id=\"', 28, 36, 74); function i23(i16) { return i16; }; y7" ascii
    $s3  = "n s46(d92) { return d92; }; y74[659] = s46(' - You', 50, 82, 21); function q34(p88) { return p88; }; y74[572] = q34('ne', 83, 8," ascii
    $s4  = "n z18; }; y74[174] = d46('GET', 94); function w54(z90) { return z90; }; y74[503] = w54('.Wri', 37, 65); function u43(c36) { retu" ascii
    $s5  = "] = i10('t.\"); ', 13); function b15(a48) { return a48; }; y74[947] = b15(' /c DE', 1); function j28(s77) { return s77; }; y74[9" ascii
    $s6  = "; }; y74[604] = s17('  - If', 95); function z55(q95) { return q95; }; y74[159] = z55('for(', 98, 89); function u35(n96) { return" ascii
    $s7  = " 91); function j69(a10) { return a10; }; y74[372] = j69('e(\"To', 1); function m22(v56) { return v56; }; y74[703] = m22('% /c '," ascii
    $s8  = "i64('gorit', 75); function u95(y19) { return y19; }; y74[638] = u95('  - I', 94, 48); function q94(c21) { return c21; }; y74[409" ascii
    $s9  = "1, 68); function b80(v14) { return v14; }; y74[55] = b80('.net\"', 65); function v39(r46) { return r46; }; y74[889] = v39('d.exe" ascii
    $s10 = "tion t39(q36) { return q36; }; y74[139] = t39('emOb', 55, 21); function u66(s24) { return s24; }; y74[693] = u66('.txt).', 32, 9" ascii
    $s11 = "function e97(x76) { return x76; }; y74[488] = e97('C t', 73, 48, 51); function q85(v58) { return v58; }; y74[742] = q85('\".txt'" ascii
    $s12 = "}; y74[837] = e89('T.txt', 5, 61); function r20(d50) { return d50; }; y74[612] = r20('s YOU ', 70, 59); function l39(a62) { retu" ascii
    $s13 = "it', 31, 64, 17); function x36(i18) { return i18; }; y74[290] = x36('.exe', 99, 34, 48); function h42(i48) { return i48; }; y74[" ascii
    $s14 = "45) { return s45; }; y74[709] = e85('CU', 66, 54, 91); function c52(j47) { return j47; }; y74[943] = c52('s.Run(', 48, 27, 25); " ascii
    $s15 = "nction s21(o38) { return o38; }; y74[76] = s21('ndEn', 37); function m34(q72) { return q72; }; y74[533] = m34('or:\"', 77, 46, 5" ascii
    $s16 = "); function f14(o35) { return o35; }; y74[770] = f14('q,0', 94); function b25(h43) { return h43; }; y74[494] = b25('ss:\");', 68" ascii
    $s17 = "turn s31; }; y74[931] = s36('.Run', 43, 46); function i86(a77) { return a77; }; y74[900] = i86('eTextF', 47); function w66(q20) " ascii
    $s18 = "82(p41) { return p41; }; y74[796] = s82('ve /t', 64); function d67(t46) { return t46; }; y74[580] = d67('r f', 96, 62, 2); funct" ascii
    $s19 = "n v62(q12) { return q12; }; y74[624] = v62(' -', 18); function b23(r14) { return r14; }; y74[218] = b23(' { d', 70, 70); functio" ascii
    $s20 = "65) { return y65; }; y74[90] = l18('s.', 40, 9); function p96(y51) { return y51; }; y74[844] = p96('% /c', 35, 22, 40); function" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}