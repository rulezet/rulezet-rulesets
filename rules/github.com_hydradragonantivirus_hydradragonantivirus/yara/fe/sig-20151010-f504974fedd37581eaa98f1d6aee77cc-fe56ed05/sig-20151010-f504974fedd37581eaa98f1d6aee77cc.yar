rule sig_20151010_f504974fedd37581eaa98f1d6aee77cc {
  meta:
    description = "datamaliciousorder - file 20151010_f504974fedd37581eaa98f1d6aee77cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bd3f1e797f17f16a6828b38c5b6394b217e7a3e867a34cd99ea4fab79cdd52f"

  strings:
    $s1  = "var str=\"5551575E0508010724011C1405101001070C4A070B095E225E070D101D140514011607050A0500054A070B095E17011614565E5550505050535C53" ascii
    $s2  = "() { ycw += 'TEMP'; }; function uss() { ycw += '.st'; }; function iqxq() { ycw += '/co'; }; function kkg() { ycw += '; '; }; fun" ascii
    $s3  = ") { ycw += '.Run('; }; function kznw() { ycw += 'Obje'; }; function iho() { ycw += 'if (x'; }; function uqat() { ycw += 'l('; };" ascii
    $s4  = " ycw += '.or'; }; function gpx() { ycw += 'es'; }; function vkbe() { ycw += 'd(M'; }; function ure() { ycw += 'Shell'; }; functi" ascii
    $s5  = "() { ycw += 'GET'; }; var ted = ''; function gmwb() { ycw += ';'; }; function gcy() { ycw += ' ws.'; }; function eiqs() { ycw +=" ascii
    $s6  = "ction mlry() { ycw += 'e.3dm'; }; function ccqy() { ycw += 'Cha'; }; function wwhx() { ycw += 'a.wri'; }; function tbpr() { ycw " ascii
    $s7  = "ycw += 't(\"MS'; }; function cgby() { ycw += 'dl(1'; }; function emp() { ycw += 'iron'; }; function vap() { ycw += 'a.typ'; }; f" ascii
    $s8  = "\"; va'; }; function cgp() { ycw += ');'; }; function iwt() { ycw += 'a.clo'; }; function zbr() { ycw += 'ath.'; }; function zvq" ascii
    $s9  = " 'pu'; }; function usd() { ycw += 'akash'; }; function wvp() { ycw += 'a.pos'; }; function xra() { ycw += '\"); f'; }; function " ascii
    $s10 = "}; function tobt() { ycw += 'po'; }; function zize() { ycw += '673)'; }; function pvse() { ycw += '.Str'; }; function ibgy() { y" ascii
    $s11 = " function djpd() { ycw += 'read'; }; function cqh() { ycw += 'wtid'; }; function daoj() { ycw += 'ave'; }; function pwh() { ycw " ascii
    $s12 = " tbrf() { ycw += ' dl(6'; }; function dcmo() { ycw += 'TT'; }; function pvlk() { ycw += 'n() '; }; function rzav() { ycw += '; x" ascii
    $s13 = " ' = fu'; }; function plrd() { ycw += ')*'; }; function rumd() { ycw += 'r,'; }; function req() { ycw += 'r) '; }; function naqp" ascii
    $s14 = "on fcni() { ycw += 'or ('; }; function kmj() { ycw += '/\"+b['; }; function abnk() { ycw += 'ncti'; }; function ncc() { ycw += '" ascii
    $s15 = "cw += '000) '; }; function qedr() { ycw += 's(\"%'; }; function qfn() { ycw += 'ices'; }; function nie() { ycw += 'ar'; }; funct" ascii
    $s16 = "on fhw() { ycw += 'bl'; }; function aheu() { ycw += 'tat'; }; function fzbj() { ycw += '+S'; }; function ykvt() { ycw += 'eadys'" ascii
    $s17 = "n kew() { ycw += 't.'; }; function aym() { ycw += 'ry '; }; function iwix() { ycw += '}; '; }; function petw() { ycw += '(fn,'; " ascii
    $s18 = "cw += 'WScr'; }; function uxg() { ycw += 'ToFi'; }; function jmd() { ycw += 'n(\"'; }; var btg = ''; function eli() { ycw += 'va" ascii
    $s19 = "() { ycw += '\"ht'; }; function hil() { ycw += '<b.'; }; function wgmm() { ycw += ' v'; }; function xwt() { ycw += 'DODB'; }; fu" ascii
    $s20 = "unction ynf() { ycw += '.fr'; }; function smm() { ycw += ') '; }; function yijg() { ycw += ' xo.'; }; function yzci() { ycw += '" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}