rule sig_20150922_c17757ff4b09a9d26c620df6f7ac3502 {
  meta:
    description = "datamaliciousorder - file 20150922_c17757ff4b09a9d26c620df6f7ac3502.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "387a0d5dcaacd7716fc3d053b740fb1e02d5c7a6c59aed782058088f172692e0"

  strings:
    $s1  = "function fnomvut() { ytlv += 'funct'; }; function zdhnjha() { ytlv += '+St'; }; function jogtxfu() { ytlv += '.com\"'; }; functi" ascii
    $s2  = "function fnomvut() { ytlv += 'funct'; }; function zdhnjha() { ytlv += '+St'; }; function jogtxfu() { ytlv += '.com\"'; }; functi" ascii
    $s3  = "function jlsb() { ytlv += 'o.R'; }; function zreql() { ytlv += '(); x'; }; function qkftpwj() { ytlv += '} c'; }; function jgrsc" ascii
    $s4  = "function jlsb() { ytlv += 'o.R'; }; function zreql() { ytlv += '(); x'; }; function qkftpwj() { ytlv += '} c'; }; function jgrsc" ascii
    $s5  = "function gklsoeu() { ytlv += '; '; }; function inotml() { ytlv += 'try'; }; function jypw() { ytlv += ' (e'; }; function dzue() " ascii
    $s6  = "{ ytlv += 'er) {'; }; function wuksh() { ytlv += '.sta'; };" fullword ascii
    $s7  = "function jyru() { ytlv += 'http'; }; function pazo() { ytlv += 'ile'; }; function nvsqc() { ytlv += 'tiv'; }; function ylpvdta()" ascii
    $s8  = "function jyru() { ytlv += 'http'; }; function pazo() { ytlv += 'ile'; }; function nvsqc() { ytlv += 'tiv'; }; function ylpvdta()" ascii
    $s9  = "glzt(); qikvzuh(); egeskwn(); kkgeg(); mmvngea(); ckcfu(); zprq(); clovhj(); uhbjup(); gxdhylb(); jgrscy(); otctrak(); zxswd(); " ascii
    $s10 = "i() { ytlv += 'ADODB'; }; function iptzn() { ytlv += 'y); '; };" fullword ascii
    $s11 = "function pnsw() { ytlv += '\")'; }; function uzdos() { ytlv += 'ch ('; }; function sccbf() { ytlv += 'ws.Ex'; }; function uceofl" ascii
    $s12 = "function fcudezv() { ytlv += 'a.ty'; }; function oziypaf() { ytlv += 'rite'; }; function itej() { ytlv += 'send'; }; function qm" ascii
    $s13 = "() { ytlv += '= '; }; function mhdki() { ytlv += '\"ay'; };" fullword ascii
    $s14 = "function oazec() { ytlv += '1) b'; }; function dzurt() { ytlv += 'r '; }; function smvmjl() { ytlv += 'afm'; }; function okeomzt" ascii
    $s15 = "var str=\"5550515E0D0A020B24011C1405101001070C4A070B09\";function uhkew() { ytlv += 'eXO'; }; function vnkt() { ytlv += ' fn'; }" ascii
    $s16 = "function fcudezv() { ytlv += 'a.ty'; }; function oziypaf() { ytlv += 'rite'; }; function itej() { ytlv += 'send'; }; function qm" ascii
    $s17 = "function otctrak() { ytlv += 'om()'; }; function mwjkvfz() { ytlv += ' d'; }; function kkgeg() { ytlv += 'ode('; }; function bth" ascii
    $s18 = "function viycew() { ytlv += 'ar xa'; }; function xdec() { ytlv += 'se)'; }; function qwqlgdx() { ytlv += 'r+'; }; function matbm" ascii
    $s19 = "function vwwj() { ytlv += 'MLHT'; }; function fjryac() { ytlv += '; i<b'; }; function irvhgx() { ytlv += ' v'; }; function bqzzv" ascii
    $s20 = "function eivrvl() { ytlv += ' n'; }; function amxff() { ytlv += ' = '; }; function nqawa() { ytlv += 'nr'; }; function ebaunj() " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}