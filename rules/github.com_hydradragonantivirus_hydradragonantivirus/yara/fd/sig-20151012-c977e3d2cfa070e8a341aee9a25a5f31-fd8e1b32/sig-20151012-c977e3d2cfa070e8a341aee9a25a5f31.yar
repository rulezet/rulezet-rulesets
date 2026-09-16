rule sig_20151012_c977e3d2cfa070e8a341aee9a25a5f31 {
  meta:
    description = "datamaliciousorder - file 20151012_c977e3d2cfa070e8a341aee9a25a5f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "665c9300983b134d6cd3e956c88184dbd84beee14337bf7e29cddcf4f33c4eb8"

  strings:
    $s1  = "var str=\"5551575E0B14011605100D0B0A17240C160A0111160B14014A070B095E225E010A0116070B0A174903111701104A160B5E17011614565E55505050" ascii
    $s2  = "yj += ' bre'; }; function pboj() { phyj += 'Run'; }; function ncwo() { phyj += 'xa.s'; }; function tpzn() { phyj += '92'; }; fun" ascii
    $s3  = "muvj() { phyj += '; '; }; function wgc() { phyj += 'ready'; }; function gww() { phyj += 'h.ro'; }; function jspc() { phyj += 'al" ascii
    $s4  = " { phyj += 's.'; }; function qgs() { phyj += 'read'; }; function bgyq() { phyj += 'ge ='; }; function iops() { uvgu = this[kaz];" ascii
    $s5  = "hyj += '; xa'; }; function ixrp() { phyj += '[i'; }; function lyts() { phyj += 'o.sta'; }; function lbmi() { phyj += '& x'; }; f" ascii
    $s6  = "b() { phyj += '\"+b'; }; function tduk() { phyj += 'g.f'; }; function eag() { phyj += '); x'; }; function kkvb() { phyj += 'com'" ascii
    $s7  = "= ');'; }; function lgot() { phyj += 'ize'; }; function mxrl() { phyj += '33'; }; function eje() { phyj += 'o.'; }; function fnl" ascii
    $s8  = "}; function qhcv() { phyj += 'e(fn'; }; function qfb() { phyj += 'eat'; }; function mbw() { phyj += '{ '; }; function upnb() { p" ascii
    $s9  = "x() { phyj += 'dl('; }; function cmvd() { phyj += 'or ('; }; function iog() { phyj += ' W'; }; function srt() { phyj += 'cr'; };" ascii
    $s10 = "unction lsd() { phyj += ')+Mat'; }; function goh() { phyj += 'ype'; }; function jvn() { phyj += ' xa '; }; function uen() { phyj" ascii
    $s11 = "() { phyj += '(8'; }; function gsc() { phyj += '2.X'; }; function qwuq() { phyj += 'iro'; }; function fknj() { phyj += '; } '; }" ascii
    $s12 = "() { phyj += 'MLH'; }; function smpd() { phyj += 'sp'; }; function dzxa() { phyj += 'var '; }; function miv() { phyj += '*100'; " ascii
    $s13 = "phyj += 'nc'; }; function qleu() { phyj += 'dom'; }; function ntjn() { phyj += 'xa.t'; }; function nlj() { phyj += 'if (x'; }; f" ascii
    $s14 = " function vdi() { phyj += '()'; }; function qjsm() { phyj += '(12'; }; function mlir() { phyj += '\"); f'; }; function ochg() { " ascii
    $s15 = "(); rol(); jspc(); mifr(); lcrd(); xxpp(); uen(); dvw(); hoef(); kkvb(); palt(); pvyh(); pfkh(); jtr(); vgf(); lqd(); lij(); gvq" ascii
    $s16 = " lqd() { phyj += 'icsch'; }; function tnet() { phyj += 'osi'; }; function bwn() { phyj += ' ='; }; function uaj() { phyj += 'r/?" ascii
    $s17 = ".co'; }; function aepi() { phyj += ',\"h'; }; function fvi() { phyj += '//'; }; function yrq() { phyj += 'P\"); '; }; function k" ascii
    $s18 = " += 'on'; }; function xwjh() { phyj += ' fu'; }; var uvgu = ''; function sgyq() { phyj += ']+\"/c'; }; function bcxt() { phyj +=" ascii
    $s19 = "; function eylo() { phyj += '}; xa'; }; function smut() { phyj += '\"WS'; }; function elvq() { phyj += 'bj'; }; function kcu() {" ascii
    $s20 = "phyj += 'ndEnv'; }; function gnrc() { phyj += 'y { w'; }; function lij() { phyj += 'oo'; }; function palt() { phyj += ' vidy'; }" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}