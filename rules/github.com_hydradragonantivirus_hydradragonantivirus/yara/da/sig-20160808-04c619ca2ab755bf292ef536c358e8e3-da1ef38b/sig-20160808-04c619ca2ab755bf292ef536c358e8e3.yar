rule sig_20160808_04c619ca2ab755bf292ef536c358e8e3 {
  meta:
    description = "datamaliciousorder - file 20160808_04c619ca2ab755bf292ef536c358e8e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b6f419be5ed307028344ab8199eab9d06ceb1c8b0de811e264c9fd6c3aa033c"

  strings:
    $x1  = "var v25 = new Array(); function i43(u47,w80) { v25[u47] = w80; }; function p87(w96) { return w96; }; i43(787,p87('KC')); functio" ascii
    $s2  = "2,c40('s.Ex')); function q29(w96) { return w96; }; i43(773,q29('F /D ')); function z99(w96) { return w96; }; i43(417,z99('e:\"')" ascii
    $s3  = "i43(614,e72('E ALL')); function w55(w96) { return w96; }; i43(713,w55('% /c ')); function b44(w96) { return w96; }; i43(920,b44(" ascii
    $s4  = "n o32(w96) { return w96; }; i43(886,o32('% /c n')); function e99(w96) { return w96; }; i43(184,e99('+n')); function j76(w96) { r" ascii
    $s5  = "96) { return w96; }; i43(849,n51('y /y ')); function r65(w96) { return w96; }; i43(586,r65('e(\"')); eval(v25.join(\"\"));" fullword ascii
    $s6  = "y50(' /c RE')); function a55(w96) { return w96; }; i43(581,a55('ine(\"')); function q57(w96) { return w96; }; i43(616,q57('FIL')" ascii
    $s7  = "w96; }; i43(923,i95('% /c D')); function e17(w96) { return w96; }; i43(439,e17('ine(\"\"')); function i20(w96) { return w96; }; " ascii
    $s8  = "5('le(f')); function z16(w96) { return w96; }; i43(830,z16('+\" \"+c')); function l91(w96) { return w96; }; i43(92,l91('TEMP%\"'" ascii
    $s9  = "43('n ')); function e36(w96) { return w96; }; i43(885,e36('EC')); function n39(w96) { return w96; }; i43(891,n39('+\".txt')); fu" ascii
    $s10 = "ction k48(w96) { return w96; }; i43(828,k48('+\".txt')); function d27(w96) { return w96; }; i43(68,d27('l\"')); function f98(w96" ascii
    $s11 = "ction t90(w96) { return w96; }; i43(79,t90('TEMP%\"')); function q34(w96) { return w96; }; i43(943,q34('); ws')); function p38(w" ascii
    $s12 = "{ return w96; }; i43(141,o74('.txt\")')); function c42(w96) { return w96; }; i43(185,c42(', f')); function l44(w96) { return w96" ascii
    $s13 = "43(839,i34('.txt\"')); function m94(w96) { return w96; }; i43(778,m94(',0,0);')); function z26(w96) { return w96; }; i43(63,z26(" ascii
    $s14 = "6; }; i43(750,o30('.txt\"+')); function l26(w96) { return w96; }; i43(396,l26('eLine')); function c40(w96) { return w96; }; i43(" ascii
    $s15 = "); function o50(w96) { return w96; }; i43(231,o50('xe\",')); function k50(w96) { return w96; }; i43(228,k50('.Run(f')); function" ascii
    $s16 = "n w96; }; i43(709,u24('s.Run(')); function b38(w96) { return w96; }; i43(355,b38('es')); function c64(w96) { return w96; }; i43(" ascii
    $s17 = "96) { return w96; }; i43(122,h91('Script')); function w78(w96) { return w96; }; i43(752,w78('0,0')); function q39(w96) { return " ascii
    $s18 = "'.Run')); function v92(w96) { return w96; }; i43(600,v92('in')); function y40(w96) { return w96; }; i43(796,y40('+\"open')); fun" ascii
    $s19 = "u73('ns.')); function l58(w96) { return w96; }; i43(843,l58('.Run(')); function u56(w96) { return w96; }; i43(650,u56('at')); fu" ascii
    $s20 = "i43(402,p57('l:\"')); function a44(w96) { return w96; }; i43(394,a44(' fp.')); function z20(w96) { return w96; }; i43(776,z20('e" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}