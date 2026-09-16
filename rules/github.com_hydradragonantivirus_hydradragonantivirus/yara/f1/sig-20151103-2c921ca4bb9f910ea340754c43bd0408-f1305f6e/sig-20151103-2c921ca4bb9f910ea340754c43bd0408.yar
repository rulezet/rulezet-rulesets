rule sig_20151103_2c921ca4bb9f910ea340754c43bd0408 {
  meta:
    description = "datamaliciousorder - file 20151103_2c921ca4bb9f910ea340754c43bd0408.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92d7fda56ac55ee479a3a38fde013655ba6fbf4cbd91cf647aef140ee4f3f430"

  strings:
    $s1  = "var str=\"5552575E0A0D0108174A0E0501070F0108240901100508090D0A00174A070B095E3C5E0A050D08171705080B0A101107170B0A4A070B095E17555E" ascii
    $s2  = "ction u4(){return 'WScript';};function t6(){return ' if (x';};function y5(){return '= WScr';};function l6(){return 'n(\"GET\"';}" ascii
    $s3  = "unction l0(){return '000) ';};function y3(){return 'osition';};function o4(){return ') { }; ';};function a2(){return 'n.com';};f" ascii
    $s4  = "n';};function h9(){return 'pt.Cre';};function d6(){return 't(\"WS';};function l7(){return '.exe\",';};function r5(){return 'send" ascii
    $s5  = "on n6(){return '.Shell';};function z9(){return 'ite(x';};function i2(){return '\"534227';};function e8(){return 'o.statu';};func" ascii
    $s6  = "nction h6(){return ' arivus';};function y6(){return 'ipt.Cre';};function t1(){return '83236';};function e7(){return 'ateObj';};f" ascii
    $s7  = "unction o6(){return 'Run(f';};function g9(){return 'r xo ';};function m4(){return 'r xa ';};function g4(){return 'andEnvi';};fun" ascii
    $s8  = "tion x4(){return 'ws.Exp';};function k2(){return 'h (er';};function n8(){return 'o.ope';};function p4(){return 'ennedy.';};funct" ascii
    $s9  = ";';};function i6(){return 'o.res';};function p5(){return '[i]+\"';};function l5(){return 'dy); i';};function d1(){return '\"); v" ascii
    $s10 = "';};function t4(){return eval;};function v0(){return 'ampark.';};function a9(){return 'com k';};function z7(){return 'f (xa.s';}" ascii
    $s11 = "n g5(){return '/count';};function x8(){return 'i<b.len';};function n7(){return 'xa.ope';};function g0(){return ' { }; ';};functi" ascii
    $s12 = "ction u1(){return '(var ';};function g7(){return 'p://\"+b';};function u0(){return 'n+n+\"';};function b4(){return '=\"+str+';};" ascii
    $s13 = "nction h4(){return 'ld = ';};function j8(){return '5\"+n,';};function s8(){return 'MLHTT';};function l9(){return ' \"pdelu';};fu" ascii
    $s14 = "n w4(){return 'exe\",2)';};function c4(){return 'gs(\"%TE';};function e3(){return 'ToFile(';};function c2(){return '{ dn = ';};f" ascii
    $s15 = "unction m8(){return 'ch (er)';};function u3(){return 'dn = ';};function v9(){return '++) { ';};function c3(){return 'm\".sp';};f" ascii
    $s16 = "on y2(){return 'ect(\"';};function c9(){return ' { ld =';};function b9(){return '.type ';};function o2(){return '); }; ';};funct" ascii
    $s17 = "on q3(){return ' var ';};function x5(){return 'teObjec';};var o1 = '';function u2(){return '\"); va';};function j3(){return '}; " ascii
    $s18 = "ction e6(){return ' var ';};function f8(){return 'am\");';};function m7(){return '1; xa.p';};function e0(){return '=ld; ';};func" ascii
    $s19 = "ion t5(){return '.Crea';};function s5(){return '= 1; ';};function c1(){return '200) { ';};function w7(){return 'if (dn ';};funct" ascii
    $s20 = "unction y9(){return '; try ';};function r1(){return '{ ws.';};function p9(){return 'n(); xa';};function o7(){return ',\"htt';};f" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}