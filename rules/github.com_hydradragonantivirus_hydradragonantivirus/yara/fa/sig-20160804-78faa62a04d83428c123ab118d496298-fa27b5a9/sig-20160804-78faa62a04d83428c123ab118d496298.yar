rule sig_20160804_78faa62a04d83428c123ab118d496298 {
  meta:
    description = "datamaliciousorder - file 20160804_78faa62a04d83428c123ab118d496298.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bccfbbac9e596e8f021ed915557925f109a5a7b9bb657185681422b0b504861"

  strings:
    $x1  = "var a16 = new Array(); function b72(t46) { return t46; }; a16[142] = b72('\"))', 16, 55); function v43(g26) { return g26; }; a16" ascii
    $s2  = "3('.dll', 44); function w30(f25) { return f25; }; a16[173] = w30('ad+\"&i', 86); function e64(w19) { return w19; }; a16[687] = e" ascii
    $s3  = " return e94; }; a16[233] = r90('+\".ex', 92, 89, 29); function z17(m98) { return m98; }; a16[46] = z17('.com\",', 54, 52, 47); f" ascii
    $s4  = " return u30; }; a16[781] = a53('s+\"com', 58, 96); function z13(j92) { return j92; }; a16[796] = z13('.txt', 89, 62, 83); functi" ascii
    $s5  = " va', 25, 81, 95); function v16(w17) { return w17; }; a16[594] = v16('  - ', 84, 15, 27); function n33(r93) { return r93; }; a16" ascii
    $s6  = "] = y79('  - ', 90); function x18(p73) { return p73; }; a16[435] = x18('sear', 25, 96, 23); function i79(y28) { return y28; }; a" ascii
    $s7  = " 64, 17, 98); function k95(w79) { return w79; }; a16[653] = k95(' - Yo', 76); function o98(m30) { return m30; }; a16[389] = o98(" ascii
    $s8  = "a16[175] = s82('id+\"&', 80, 85, 21); function t64(x16) { return x16; }; a16[834] = t64(' /c c', 5, 93, 42); function w77(f69) {" ascii
    $s9  = "(' /c no', 74, 8, 32); function u97(y82) { return y82; }; a16[788] = u97('/D \"+c', 13); function g71(r13) { return r13; }; a16[" ascii
    $s10 = "77; }; a16[769] = a71('\"+cq+\"', 19, 22, 70); function a86(d62) { return d62; }; a16[766] = a86('% /c ', 87); function t48(l97)" ascii
    $s11 = "3] = u73('\"+cq+f', 16); function o62(q33) { return q33; }; a16[912] = o62(' /c DE', 39, 20, 44); function c83(h88) { return h88" ascii
    $s12 = "eturn i58; }; a16[812] = o59('.txt', 71); function t19(b96) { return b96; }; a16[832] = t19('SP', 21, 77, 75); function w20(y67)" ascii
    $s13 = ") { return i59; }; a16[298] = d93('\".txt', 82); function s95(x33) { return x33; }; a16[875] = s95('exe', 93, 48, 37); function " ascii
    $s14 = "return f69; }; a16[681] = w77('manu', 17, 82, 90); function y10(u48) { return u48; }; a16[94] = y10('%TEMP', 8, 89, 65); functio" ascii
    $s15 = "207] = a29('xa.s', 5, 68, 75); function t17(n76) { return n76; }; a16[141] = t17('+\".txt', 65); function x11(q73) { return q73;" ascii
    $s16 = " = z69('F /D', 21); function f59(k77) { return k77; }; a16[443] = f59('fp.Wri', 58, 83, 2); function b47(v54) { return v54; }; a" ascii
    $s17 = "a16[276] = a78('.exe\")', 12); function i69(b60) { return b60; }; a16[55] = i69('lo', 1); function a29(j45) { return j45; }; a16" ascii
    $s18 = "n j10; }; a16[879] = v47('t\"+', 15, 28); function i65(b61) { return b61; }; a16[212] = i65('\".exe\"', 76); function r29(b84) {" ascii
    $s19 = "12(d26) { return d26; }; a16[103] = i12('Script', 25, 44, 30); function u33(n79) { return n79; }; a16[736] = u33('; ws', 41, 17)" ascii
    $s20 = ", 2); function m84(b74) { return b74; }; a16[737] = m84('.Run(', 50, 36); function g55(e38) { return e38; }; a16[410] = g55('ttp" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}