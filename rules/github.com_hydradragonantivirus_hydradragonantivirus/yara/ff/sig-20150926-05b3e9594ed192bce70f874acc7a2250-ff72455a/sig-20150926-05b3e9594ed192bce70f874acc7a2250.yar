rule sig_20150926_05b3e9594ed192bce70f874acc7a2250 {
  meta:
    description = "datamaliciousorder - file 20150926_05b3e9594ed192bce70f874acc7a2250.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f7445acbde5a8d05f1b0348ce1d1aea1fabf3fd144231bbc7009463902b8a50"

  strings:
    $s1  = "var str=\"5550535E0508010724011C1405101001070C4A070B095E255E1313134A0108011E4A070B094A10165E17011614565E555050575653505C555D\";f" ascii
    $s2  = "on nfzsnk() { nfxemwu += 'i=0; '; }; function nbsyfw() { nfxemwu += 'a.'; }; function fdrkce() { nfxemwu += '(\"GET'; }; functio" ascii
    $s3  = "a() { nfxemwu += 'avoi'; }; function pdap() { nfxemwu += 'om a'; }; function succo() { nfxemwu += 'Run(f'; }; function vkrfeap()" ascii
    $s4  = "h.'; }; function iyrby() { nfxemwu += 'EMP%'; }; function vttqg() { nfxemwu += 'va'; }; function ynyynt() { nfxemwu += 'g.fro'; " ascii
    $s5  = "() { nfxemwu += 'ar '; }; function dkjask() { nfxemwu += 'ar'; }; function ygisjz() { nfxemwu += 'a.pos'; }; function nonjl() { " ascii
    $s6  = "; }; function pfohdvw() { nfxemwu += '+b'; }; function mjooil() { nfxemwu += 'bject'; }; function rcqoqwm() { nfxemwu += 'o.onr'" ascii
    $s7  = "emwu += '.ne'; }; function dyvdm() { nfxemwu += '.sav'; }; function fwglp() { nfxemwu += '00)'; }; function ophtb() { nfxemwu +=" ascii
    $s8  = "xemwu += ' xa'; }; function gdsacv() { nfxemwu += 'send'; }; function gipzy() { nfxemwu += '.Res'; }; function iwiby() { nfxemwu" ascii
    $s9  = "function xpcp() { nfxemwu += '.writ'; }; function ynde() { nfxemwu += '\"+fr'; }; function ddxu() { nfxemwu += 'b.len'; }; funct" ascii
    $s10 = "emwu += 'm('; }; function nijonim() { nfxemwu += '(\"%T'; }; function mduf() { nfxemwu += '(17'; }; function qcuomq() { nfxemwu " ascii
    $s11 = "+= 'eak; '; }; function bndk() { nfxemwu += 'ws'; }; function yzchhj() { nfxemwu += ' try'; }; function wtkvmy() { nfxemwu += 't" ascii
    $s12 = "nfxemwu += '\"+str'; }; function opgh() { nfxemwu += 'gth; '; }; function yifcv() { nfxemwu += '+Ma'; }; function wylgru() { nfx" ascii
    $s13 = ") { nfxemwu += 'veXO'; }; function cwfe() { nfxemwu += ' x'; }; function bxwicb() { nfxemwu += 'rin'; }; function bvpyi() { nfxe" ascii
    $s14 = "ction zgaq() { nfxemwu += ' A'; }; function dxrn() { nfxemwu += '1ser'; }; function dbkhnqh() { nfxemwu += ' dl(5'; }; function " ascii
    $s15 = "emwu += 'vice'; }; function cvgcedd() { nfxemwu += 'd(Ma'; }; function kgis() { nfxemwu += '\",'; }; var hcigy = ''; function fz" ascii
    $s16 = "'f ('; }; function nfsayu() { nfxemwu += '=='; }; function xhfn() { nfxemwu += 'r b'; }; function buevp() { nfxemwu += ']+'; }; " ascii
    $s17 = " function faqmox() { nfxemwu += 'ha'; }; function wdkiie() { nfxemwu += '[i'; }; function ypzjgac() { nfxemwu += 'tus ='; }; fun" ascii
    $s18 = " nfxemwu += ' xa.o'; }; function hrzybfx() { nfxemwu += '23)'; }; function japp() { nfxemwu += ' = 1;'; }; function hzud() { nfx" ascii
    $s19 = "xemwu += '{}; i'; }; function lvqppb() { nfxemwu += 'ce2'; }; function mhvvqdo() { nfxemwu += 'id='; }; function pmbmfna() { nfx" ascii
    $s20 = " { nfxemwu += 'ead'; }; function gryw() { nfxemwu += '://\"'; }; function wzudmo() { nfxemwu += ', fa'; }; function axfig() { nf" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}