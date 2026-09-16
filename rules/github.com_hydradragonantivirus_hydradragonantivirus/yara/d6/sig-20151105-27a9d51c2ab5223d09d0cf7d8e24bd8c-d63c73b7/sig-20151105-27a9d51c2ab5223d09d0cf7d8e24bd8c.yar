rule sig_20151105_27a9d51c2ab5223d09d0cf7d8e24bd8c {
  meta:
    description = "datamaliciousorder - file 20151105_27a9d51c2ab5223d09d0cf7d8e24bd8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7f2d711d96e08c7279ad70ed9b6fdad0be53d6753c8b7ac306a566d1be63f55"

  strings:
    $s1  = "var str=\"5552505E0C160A240C160A0111160B14014A070B095E3C5E050F051D0F05160B4A070B095E17555E555050525354545D5D5C5E55\";function w1" ascii
    $s2  = "{return 'Shell\"';};function a3(){return '{ for';};function x3(){return '\".exe\",';};function y7(){return ' (var ';};function r" ascii
    $s3  = "{return 'om j-hs';};function g5(){return 'e); xo';};function v9(){return 'on = ';};function b4(){return 'u.com n';};function j4(" ascii
    $s4  = " '2.XMLH';};function x7(){return ' i<b.l';};function i0(){return '== 20';};function s1(){return 't.com';};function p7(){return '" ascii
    $s5  = "rn 'tatus ';};function z3(){return 'n == ';};function p0(){return 'n<=3; ';};function n5(){return 'TEMP%';};function l4(){return" ascii
    $s6  = "ar ';};function b9(){return '//\"+b[i';};function h7(){return '; }; x';};function u7(){return 'Script.';};function y3(){return '" ascii
    $s7  = "';};function j6(){return '\"GET\"';};function r9(){return 'TTP\")';};function v6(){return '3828\"+n';};function w4(){return '1; " ascii
    $s8  = ";};function u1(){return '; i++';};function q9(){return '{ ws.Ru';};function r0(){return 'ipt.Cre';};function l0(){return '\"6447" ascii
    $s9  = ",\"http:';};function k2(){return ' (xa.si';};function r7(){return ', fals';};o7+=t9();o7+=p7();o7+=h0();o7+=f4();o7+=r8();o7+=b4" ascii
    $s10 = "ea';};function b2(){return 'r ld ';};function b5(){return 'te(xo.';};function e0(){return 'ect(\"';};function e7(){return 'xa.wr" ascii
    $s11 = "eturn 's.Exp';};function f4(){return 'cess2.c';};function f1(){return 'n+n+\".';};function a8(){return 'str+\"&r';};function l5(" ascii
    $s12 = "dn ';};function j1(){return 'fn = w';};function m3(){return '.send';};function p9(){return 'ing.f';};function w8(){return 'dy); " ascii
    $s13 = ")+';};function d8(){return '); try ';};function w3(){return ') { v';};function w0(){return '7\"; va';};function z2(){return '); " ascii
    $s14 = " (e';};function h5(){return 'er) { }';};function r3(){return 'ODB.S';};function j7(){return 'e(); }';};function n0(){return 'ar " ascii
    $s15 = "a';};function v1(){return 'n(fn+n+';};function d9(){return 'ings(\"%';};function u6(){return 'teObje';};function l8(){return '(9" ascii
    $s16 = "var str=\"5552505E0C160A240C160A0111160B14014A070B095E3C5E050F051D0F05160B4A070B095E17555E555050525354545D5D5C5E55\";function w1" ascii
    $s17 = " i';};function x9(){return 'ct(\"AD';};function l9(){return '1) { ';};function t0(){return 'nter/';};function b6(){return 'ze > " ascii
    $s18 = "return '?id=\"+';};function g9(){return '); va';};function k7(){return 'respo';};function p1(){return ' = WScr';};function m8(){" ascii
    $s19 = "if';};function y9(){return '(\" \"); ';};function h6(){return ' WScr';};function o4(){return 'aveToF';};function q6(){return 't." ascii
    $s20 = "{return 'positi';};function z6(){return 'nseBo';};function w9(){return '; bre';};function x6(){return 'var ws';};function v3(){r" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}