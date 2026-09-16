rule sig_20151111_d761ea8b891f99e290e4d2963bffdd7a {
  meta:
    description = "datamaliciousorder - file 20151111_d761ea8b891f99e290e4d2963bffdd7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05a7edacfb464f005298196a70718c17bb291e6df79e3f862707e94698d3fefa"

  strings:
    $s1  = "var str=\"5552505E0A0D0108174A0E0501070F0108240901100508090D0A00174A070B095E3C5E050C0B1117010B020216050316050A07014A070B4A110F5E" ascii
    $s2  = "function q4(){return 'atus ==';};function l3(){return '(\"MSXML';};function p1(){return '%TEMP%';};function v6(){return ' (er) {" ascii
    $s3  = "7555E555050535655505750565E55\";function o0(){return '.com\"';};function t2(){return ' xo.o';};function c4(){return ' }; };';};f" ascii
    $s4  = "function u1(){return '.exe\",1';};function y7(){return 'b.lengt';};function q5(){return 'for (';};function i0(){return '.resp';}" ascii
    $s5  = " '); xo.';};function e7(){return '.Shell';};function i3(){return 'bject';};function r7(){return '{ xa.o';};function c0(){return " ascii
    $s6  = "turn ')+\"25';};function x9(){return 'nd=7557';};function f7(){return 'ipt.Cre';};function m0(){return ' xa.ty';};function a1(){" ascii
    $s7  = ";function h1(){return 'h; i+';};function j9(){return 'ript.';};function a5(){return ' n=1; ';};function p4(){return 'xa.sav';};f" ascii
    $s8  = " 'akres';};function y2(){return 'are.co';};function t9(){return ' ws.Run';};function c6(){return ' catch';};m8+=i1();m8+=e6();m8" ascii
    $s9  = "turn 'n<=3; n';};function f1(){return 'le(fn';};function y9(){return ' };';};function q9(){return 'de(92';};function m7(){return" ascii
    $s10 = "unction g4(){return 'd; i<';};function b3(){return '++) { ';};function j1(){return ' var ws';};function w0(){return 'var xo ';};" ascii
    $s11 = "nction x3(){return '= 0; ';};function k3(){return 'ings(\"';};function q2(){return '+) { v';};function k1(){return 'ar ld =';};f" ascii
    $s12 = "cript';};function u0(){return '(\" \");';};function w4(){return 'xa.cl';};function z9(){return 'n = 0; ';};function n7(){return " ascii
    $s13 = "nseBod';};function h2(){return 'iraga';};function f5(){return 'eToFi';};function a2(){return 'send();';};function w2(){return '9" ascii
    $s14 = "}; }';};function a0(){return ' ld = i';};function y5(){return ' false';};function i8(){return 'm\"); v';};function f8(){return '" ascii
    $s15 = "',0); } ';};function d2(){return 'ect(\"W';};function r8(){return '(fn+n+\"';};function z5(){return '+\"/co';};function b8(){ret" ascii
    $s16 = " ' if (';};function l7(){return 'kumde';};function f9(){return eval;};function m5(){return '(\"ADODB';};function g1(){return 'pa" ascii
    $s17 = "== 1) {';};function d4(){return '\"); var';};function n8(){return '; brea';};function t8(){return 'CharCo';};function c1(){retur" ascii
    $s18 = " '/\"+b[i]';};function u4(){return '{ dn = ';};function i1(){return 'var b =';};function p3(){return ' (er) {';};function e5(){r" ascii
    $s19 = " '1; xa.p';};function u3(){return ' = WScr';};function v1(){return 'llery';};function h0(){return 'ose();';};function v0(){retur" ascii
    $s20 = "' ws.Ex';};function g9(){return 'Create';};function s1(){return 'ositio';};function a3(){return '= WSc';};function v5(){return '" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}