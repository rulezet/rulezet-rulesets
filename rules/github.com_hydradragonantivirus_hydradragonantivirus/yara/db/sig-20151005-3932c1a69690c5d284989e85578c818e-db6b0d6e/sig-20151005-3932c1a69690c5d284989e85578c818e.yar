rule sig_20151005_3932c1a69690c5d284989e85578c818e {
  meta:
    description = "datamaliciousorder - file 20151005_3932c1a69690c5d284989e85578c818e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07feb6c94635046bb1a779955c7c79c36f67018da7cbb4d70176824430b2234b"

  strings:
    $s1  = "var str=\"5551555E0D0A020B24011C1405101001070C4A070B095E225E0A0B16100C12050808011D1016050D0A0D0A034A070B095E17011614565E55505050" ascii
    $s2  = "i += 'e >'; }; function kjm() { tvzi += '00)+'; }; function pve() { tvzi += 'Activ'; }; function ryf() { tvzi += 'y.com'; }; fun" ascii
    $s3  = "zi += '; };'; }; function gza() { tvzi += 'L2.'; }; function usk() { tvzi += ' = 0'; }; function wjn() { tvzi += 'GET\"'; }; fun" ascii
    $s4  = ") { tvzi += 'reak'; }; function kzwb() { tvzi += '.net\"'; }; function woml() { tvzi += 'g.f'; }; function ezip() { tvzi += 'sam" ascii
    $s5  = "tvzi += 'bjec'; }; function akey() { tvzi += '(fn'; }; function ysne() { tvzi += 'nment'; }; function thaw() { tvzi += '\"ADO'; " ascii
    $s6  = "+= 'n ='; }; function fjws() { tvzi += 'a.sav'; }; function qkix() { tvzi += '.rou'; }; function nqr() { tvzi += '63'; }; functi" ascii
    $s7  = "tion yyk() { tvzi += 'a.siz'; }; function hkm() { tvzi += 'tat'; }; function ewrw() { tvzi += 'TE'; }; function aby() { tvzi += " ascii
    $s8  = "e() { tvzi += '.s'; }; function ioad() { tvzi += 't.php'; }; function xam() { tvzi += 'n()'; }; function faag() { tvzi += 'ndE';" ascii
    $s9  = "; function uiqw() { tvzi += '\" \")'; }; function lbpe() { tvzi += 'com '; }; function mswz() { tvzi += 'r x'; }; function xgfg(" ascii
    $s10 = " mqa(); gkae(); usk(); jspq(); fjws(); plt(); tet(); nxrl(); vec(); olg(); pwi(); agq(); uqld(); akey(); sby(); nkxt(); ier(); r" ascii
    $s11 = " tvzi += '4 && '; }; function drhh() { tvzi += 'om('; }; var gni = ''; function xhk() { tvzi += 's(\"%'; }; function uhzx() { tv" ascii
    $s12 = "vzi += ' ws.R'; }; function ffw() { tvzi += ' (var'; }; function mum() { tvzi += '.typ'; }; function hes() { tvzi += 'MP%\"'; };" ascii
    $s13 = "on tunb() { tvzi += 'dl(8'; }; function tct() { tvzi += 'o.sen'; }; function fkqw() { tvzi += 'tt'; }; function xli() { tvzi += " ascii
    $s14 = "ction ccx() { tvzi += '.rea'; }; function hox() { tvzi += 'ion '; }; function kju() { tvzi += '.Resp'; }; function jqr() { tvzi " ascii
    $s15 = "+= 'TTP\")'; }; function nkkd() { tvzi += 'ready'; }; function wpx() { tvzi += 't('; }; function vec() { tvzi += '(fn,2'; }; fun" ascii
    $s16 = "zi += 'Body)'; }; function xoxy() { tvzi += ' x'; }; function kwgv() { tvzi += ') {'; }; function bgts() { tvzi += '+st'; }; fun" ascii
    $s17 = "{ tvzi += '<b.l'; }; function apbm() { tvzi += '(x'; }; function bboy() { tvzi += ' xa.w'; }; function zjs() { tvzi += 'arC'; };" ascii
    $s18 = "ction yzxx() { tvzi += 'p:'; }; function higc() { tvzi += 'ive'; }; function tji() { tvzi += ' b = '; }; function flii() { tvzi " ascii
    $s19 = " += 'XO'; }; function urmx() { tvzi += 'eXOb'; }; function ror() { tvzi += 'atch '; }; function plt() { tvzi += 'eTo'; }; functi" ascii
    $s20 = " += 'f (xo'; }; function fxh() { tvzi += 'XMLH'; }; function zhiu() { tvzi += 'nviro'; }; function rgea() { tvzi += 'ion()'; }; " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}