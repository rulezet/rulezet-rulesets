rule sig_20151008_820632a6968ec2e35ba2193d863d6e38 {
  meta:
    description = "datamaliciousorder - file 20151008_820632a6968ec2e35ba2193d863d6e38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e44a0b491b99d91a05120e3777796fcfbb93c15b3c7867e46dada6ebdaac108a"

  strings:
    $s1  = "var str=\"5551575E0508010724011C1405101001070C4A070B095E225E0F0D070F0D0A03170B110A00174A070B4A110F5E17011614565E5550505057565C5D" ascii
    $s2  = "}; function aklp() { imfh += 'te =='; }; function poi() { imfh += 'l(fr)'; }; function rqhs() { imfh += '.exe\"'; }; function qz" ascii
    $s3  = " imfh += 'xo.r'; }; function cmvi() { imfh += 'jec'; }; function hdh() { imfh += '(\"A'; }; function gws() { imfh += '\"GET'; };" ascii
    $s4  = "unction cxwf() { imfh += ' 1; '; }; function xlp() { imfh += '\",'; }; function gob() { imfh += 'o.sta'; }; function ktz() { imf" ascii
    $s5  = " 'xo.'; }; function xsb() { imfh += 'in'; }; function qyp() { imfh += 'e '; }; function ufmi() { imfh += 'g.fro'; }; function ir" ascii
    $s6  = "'.spl'; }; function zep() { imfh += 'de(92'; }; function cvzf() { imfh += '[i]+\"'; }; function wrjt() { imfh += '%TE'; }; funct" ascii
    $s7  = "z() { imfh += 'tr+'; }; function cxel() { imfh += 'com\"'; }; function wmz() { imfh += ' ('; }; function sgv() { imfh += 'try'; " ascii
    $s8  = "bmat() { imfh += '58'; }; function dnaa() { imfh += 'fal'; }; function gnyy() { imfh += 'DB.'; }; function hzl() { imfh += '.siz" ascii
    $s9  = "= 'ound('; }; function krw() { imfh += '.save'; }; function pbc() { imfh += ' i++'; }; function sdhs() { imfh += 'ch (e'; }; fun" ascii
    $s10 = "mfh += 'dn ='; }; function iqfn() { imfh += 'he'; }; var imfh = '';bcif(); eyqg(); uti(); poi(); xya(); pxic(); sqc(); bwhi(); l" ascii
    $s11 = "{ imfh += '231.'; }; function dbt() { imfh += ') { v'; }; function umla() { imfh += '\"ht'; }; function kyj() { imfh += '}; };';" ascii
    $s12 = "}; function edis() { imfh += 'er/?'; }; function ddh() { qmu = this[vwgv]; };  function bfpn() { imfh += 'Cre'; }; function crzl" ascii
    $s13 = " b'; }; function wzf() { imfh += '.onre'; }; function ijcp() { imfh += ', '; }; function ruy() { imfh += '.S'; }; function jqe()" ascii
    $s14 = " 'ti'; }; function etxw() { imfh += '2);'; }; function tgkl() { imfh += ') {'; }; function csxu() { imfh += 'r '; }; function ih" ascii
    $s15 = "dek() { imfh += 'send'; }; function zcd() { imfh += 'Stre'; }; function jqx() { imfh += 'bject'; }; function pxic() { imfh += 'r" ascii
    $s16 = "}; function bpeq() { imfh += '<b.'; }; function gylt() { imfh += 'rand'; }; function kwr() { imfh += 'ej'; }; function jit() { i" ascii
    $s17 = "f() { imfh += '/\"'; }; function lbb() { imfh += 'le(fn'; }; function fgx() { imfh += ');'; }; function xww() { imfh += '.posi';" ascii
    $s18 = "n jgym() { imfh += ' va'; }; function fxg() { imfh += '.Resp'; }; function dnnb() { imfh += 'Expan'; }; function tpdc() { imfh +" ascii
    $s19 = "652\"; function wdk() { imfh += 'se)'; }; function vwfv() { imfh += 'on '; }; function fcgo() { imfh += 'DO'; }; function mta() " ascii
    $s20 = "; function mws() { imfh += 'io'; }; function zdit() { imfh += 'am'; }; function ggmz() { imfh += 'th.r'; }; function xde() { imf" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}