rule sig_20151014_564306482449f2638bf0fa06f70bdc81 {
  meta:
    description = "datamaliciousorder - file 20151014_564306482449f2638bf0fa06f70bdc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4567e38e89ecd0e6a42ebc5673c431b7c51cf9fedc4017716ac6ddc594056af0"

  strings:
    $s1  = "var str=\"5551505E0D0A020B24011C1405101001070C4A070B095E225E08010B0705160507070117170B160D01174A070B095E17011614565E55505050535C" ascii
    $s2  = "unction hed() { bhyk = iri[jqp]; };  function ffat() { dku += 'nd('; }; function waq() { dku += '\"reye'; }; function ioh() { dk" ascii
    $s3  = "n aakq() { dku += 'Body)'; }; function pdpn() { dku += 'for '; }; function muc() { dku += '(e'; }; function tffr() { dku += 'GET" ascii
    $s4  = "tion uxg() { dku += 'ponse'; }; function rjx() { iri = this; };  function lvx() { dku += 'Run(f'; }; function wur() { dku += '=0" ascii
    $s5  = " function utz() { dku += ' w'; }; function bac() { dku += ' va'; }; function egyy() { dku += 'o.Res'; }; function mtqg() { dku +" ascii
    $s6  = "xd() { dku += '.read'; }; function kgp() { dku += 'n,1,0'; }; function amx() { dku += 'Obje'; }; function lhl() { dku += 'var ';" ascii
    $s7  = "d() { dku += '{ i'; }; function gjou() { dku += '.rou'; }; function ekj() { dku += ' =='; }; function rtv() { dku += 'dl('; }; f" ascii
    $s8  = "\"'; }; function gdgp() { dku += 'Ma'; }; function ztq() { dku += ' xa.'; }; var iri = ''; function cbyf() { dku += 's.Exp'; }; " ascii
    $s9  = "t() { dku += 'l.net'; }; function juh() { dku += '.sta'; }; function spe() { dku += 'e = 1'; }; function kis() { dku += ' ='; };" ascii
    $s10 = ";'; }; function qnvp() { dku += 'on '; }; function lom() { dku += 'LHT'; }; function uzyy() { dku += 'in'; }; function gnwg() { " ascii
    $s11 = "on ilaz() { dku += 'me'; }; function puu() { dku += '\"+st'; }; function ueo() { dku += ');'; }; function zge() { dku += ');'; }" ascii
    $s12 = " += 'f ('; }; function qkvp() { dku += ' { v'; }; function hvyy() { dku += '; }'; }; function pfj() { dku += 'eadys'; }; functio" ascii
    $s13 = "}; function ifb() { dku += 'teOb'; }; function rbgl() { dku += 'nter'; }; function fhd() { dku += 'd=\"+'; }; function czm() { d" ascii
    $s14 = "ction hmso() { dku += 'f (xo'; }; function ohr() { dku += '/?id='; }; function mtb() { dku += 'er'; }; function ojq() { dku += '" ascii
    $s15 = "}; function qkv() { dku += 'xo.'; }; function msz() { dku += '; xo'; }; function rna() { dku += '; i'; }; function yvu() { dku +" ascii
    $s16 = "6555752\"; function czy() { dku += 'ar '; }; function yzsn() { dku += 'e(92)'; }; function ige() { dku += 'ct(\"M'; }; function " ascii
    $s17 = "}; function kpi() { dku += 'cl'; }; function akz() { dku += 'lit(\"'; }; function eex() { dku += '& xo'; }; function obmq() { dk" ascii
    $s18 = "tion uze() { dku += ' > '; }; function tot() { dku += 'g.f'; }; function fvs() { dku += 'f '; }; function lczn() { dku += '00'; " ascii
    $s19 = "; }; function iego() { jqp += 'al'; };  function txoj() { dku += '.sp'; }; function jygb() { dku += 'aure'; }; function ywei() {" ascii
    $s20 = "unction nkl() { dku += 'av'; }; function iquq() { dku += '00'; }; function heo() { dku += '; dl'; }; function rslz() { dku += ' " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}