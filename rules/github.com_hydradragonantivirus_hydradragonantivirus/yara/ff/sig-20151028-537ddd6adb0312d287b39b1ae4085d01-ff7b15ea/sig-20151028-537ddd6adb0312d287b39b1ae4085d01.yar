rule sig_20151028_537ddd6adb0312d287b39b1ae4085d01 {
  meta:
    description = "datamaliciousorder - file 20151028_537ddd6adb0312d287b39b1ae4085d01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2809585765e48421cca4785c13bcbcd9c0a04d01d0b53ad4d1da18e8b27842ec"

  strings:
    $s1  = "var str=\"5552555E06160D030D240C160A0111160B14014A070B095E3C5E020516490B11104A00015E17565E555050525450505353545E55\"; function y" ascii
    $s2  = "ction svqh() { gri += 's(\"%T'; }; function edi() { gri += 'g.com'; }; function yuz() { jjx(gri); };  function fpe() { gri += 'n" ascii
    $s3  = "veT'; }; function bxwn() { gri += 'seBo'; }; function myxy() { gri += '1; x'; }; function urm() { gri += 's.c'; }; function erat" ascii
    $s4  = " function nvux() { gri += 'rac'; }; function irc() { gri += 'id'; }; function huj() { gri += 'oln'; }; function ljc() { gri += '" ascii
    $s5  = "{ gri += '; '; }; function yygd() { gri += 'w.gro'; }; function ktff() { gri += 'pe = '; }; function dvmt() { gri += 'P%\")+'; }" ascii
    $s6  = "'; }; function xfbb() { gri += 'n = w'; }; function tdj() { gri += 'a ='; }; function ntx() { gri += '.fro'; }; function bvva() " ascii
    $s7  = "; '; }; function wzm() { gri += ' xa'; }; function gdgr() { gri += '\"/c'; }; function kqzn() { gri += 'DODB.'; }; function erin" ascii
    $s8  = "; }; function jcg() { gri += 'ty'; }; function dmd() { gri += ' xa.o'; }; function quze() { gri += 'r) { '; };qgkk(); uil(); woo" ascii
    $s9  = " gri += 'viron'; }; function rgn() { gri += 'it('; }; function tpa() { gri += '+) '; }; function axxu() { gri += '.size'; }; fun" ascii
    $s10 = " gri += 'She'; }; function gwib() { gri += 'e\",1,'; }; function xgk() { gri += 'e); '; }; function pxtd() { gri += 'try'; }; fu" ascii
    $s11 = "i += 's =='; }; function hxkr() { gri += 'va'; }; function swsv() { gri += 'andEn'; }; function kqai() { gri += 'Crea'; }; funct" ascii
    $s12 = "var str=\"5552555E06160D030D240C160A0111160B14014A070B095E3C5E020516490B11104A00015E17565E555050525450505353545E55\"; function y" ascii
    $s13 = "}; function apu() { gri += 'ounte'; }; function vvt() { gri += '; '; }; function zolr() { gri += 'd(); '; }; function ylx() { gr" ascii
    $s14 = "f '; }; function tyd() { gri += '; '; }; function vjia() { gri += '};'; }; function qgkk() { gri += 'var b'; }; function vrfp() " ascii
    $s15 = "i += 'ript'; }; function dnt() { gri += 'od'; }; function xtaf() { gri += 'ET\",'; }; function hqn() { gri += 'r ('; }; function" ascii
    $s16 = "{ gri += 'teOb'; }; function vhj() { gri += 'nd=5'; }; function kifl() { gri += 'atc'; }; function rsfv() { gri += 'dy);'; }; fu" ascii
    $s17 = " function bavk() { gri += '}; i'; }; function jsc() { gri += '.c'; }; function xkb() { gri += 'ing'; }; var hjj = ''; function e" ascii
    $s18 = ") { gri += '+\"7'; }; function zgx() { gri += '\".'; }; function aaoz() { gri += 'Str'; }; function umdf() { gri += '); v'; }; f" ascii
    $s19 = "; }; function prnv() { gri += 'd '; }; function vyvt() { gri += 'f '; }; function bmcd() { gri += '\"ht'; }; function prka() { g" ascii
    $s20 = "'72024'; }; function zzpo() { gri += '= 0'; }; function imk() { gri += 'ment'; }; function dzb() { gri += '\".s'; }; function di" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}