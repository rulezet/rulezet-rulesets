rule sig_20151116_f29f2b7bf159872dac6d5759e93ce358 {
  meta:
    description = "datamaliciousorder - file 20151116_f29f2b7bf159872dac6d5759e93ce358.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a436c7610b6f0465b7a53a4ec04f2b0d756c89cf53f1e0d9c2e1d4412e1d5fd6"

  strings:
    $s1  = "var str=\"5552525E0A0D0108174A0E0501070F0108240901100508090D0A00174A070B095E3C5E00110A030711170B080B4A070B095E17555E555050535253" ascii
    $s2  = "function v9(){return ') { var';};function z7(){return 'pt.She';};function g8(){return '\"%TEMP';};function o4(){return 'teObjec'" ascii
    $s3  = " 'open(';};function b2(){return 'tch (e';};function d5(){return 're.com';};function t5(){return '.exe\",';};function z3(){return" ascii
    $s4  = "};function t0(){return 'akumd';};function b3(){return 'rings(';};function x1(){return '\"GET\"';};function h3(){return 't.Crea';" ascii
    $s5  = "xa.typ';};function d3(){return 'File(fn';};function y9(){return 't(\"ADO';};function f3(){return '\"MSXM';};function r1(){return" ascii
    $s6  = "ion d7(){return ' var ';};function c0(){return ' (xa.s';};function i0(){return '2)+\"423';};function l9(){return 'Run(f';};funct" ascii
    $s7  = "'xa.wri';};function s1(){return '{ dn =';};function w2(){return '%\")+S';};function f1(){return ' dn = ';};function w7(){return " ascii
    $s8  = "rn 'pt.Cre';};function o5(){return 'WScrip';};function z6(){return 'cript';};function h1(){return 'ateOb';};function c6(){return" ascii
    $s9  = " '1000) ';};function t3(){return 'om mon';};function h5(){return 'r) { ';};function u3(){return ',\"http';};function g5(){return" ascii
    $s10 = "35053535E55\";function c4(){return '; var ';};function j9(){return 'o.sta';};function l5(){return 'tring.f';};function a5(){retu" ascii
    $s11 = "=\"+str+';};function e5(){return '{ xo.';};function a1(){return ' for (v';};function y7(){return '.Create';};function i2(){retur" ascii
    $s12 = "ess2.co';};function d9(){return 'rCode(9';};function n6(){return '.positi';};function l2(){return '.saveTo';};function j6(){retu" ascii
    $s13 = "t(\" \")';};function y4(){return '+n+\".';};function r9(){return 'i; bre';};function u1(){return 'y); if';};function o0(){return" ascii
    $s14 = " (dn =';};function a3(){return 'send();';};function r6(){return 'e = 1; ';};function e8(){return 'pen();';};function u8(){return" ascii
    $s15 = "n ' 1; xa';};function s4(){return 'sort.c';};function n4(){return 'WScri';};function y0(){return 'romCha';};function w0(){return" ascii
    $s16 = " 'ject(\"';};function d6(){return ' (var i';};function i5(){return 'ose();';};function l3(){return '://\"+';};function d8(){retu" ascii
    $s17 = "function i8(){return '= 1) ';};function k7(){return 'var l';};function f0(){return 'n+n+\"';};function g4(){return 'var b';};fun" ascii
    $s18 = ";function w3(){return ' live';};function r5(){return 'ak; }';};function c7(){return '1; n<=3';};function a9(){return 'er) { }';}" ascii
    $s19 = "'xa = ';};function i9(){return '0; xa';};function u2(){return '<b.leng';};function y5(){return '{ ld = ';};function v3(){return " ascii
    $s20 = "&rnd';};function v1(){return ' var x';};function p6(){return '=4738';};function z5(){return 'Object(';};function x4(){return 'LH" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}