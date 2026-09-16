rule sig_20151030_5bd3636471d79a2e18b2a2f14a258eaa {
  meta:
    description = "datamaliciousorder - file 20151030_5bd3636471d79a2e18b2a2f14a258eaa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e9ca40af9760d5def535134329e972603c8b1f1ede19b883db7383cc0531752"

  strings:
    $s1  = "var str=\"5552555E160D1005240C160A0111160B14014A070B095E3C5E0F0516050B0F010E0B010211084A070B095E17555E55505052555D50515C5C5E55\"" ascii
    $s2  = "= '+n+\".'; }; function acsm() { nslx += '%TEMP'; }; function ane() { nslx += '.s'; }; function jme() { nslx += 'it(\"'; }; func" ascii
    $s3  = " += 's.Run'; }; function hbb() { nslx += '1; '; }; function txq() { nslx += ' { }'; }; function kdfq() { nslx += '&rn'; }; funct" ascii
    $s4  = " { nslx += '\"http'; }; function avvr() { nslx += 'o.sen'; }; function vhc() { nslx += 'e); x'; }; function txl() { nslx += 'ed'" ascii
    $s5  = " uia() { nslx += '(fn'; }; function nqeq() { nslx += 'GET\",'; }; function osz() { nslx += 'nmen'; }; function dqru() { nslx += " ascii
    $s6  = " += 'b.len'; }; function brbp() { nslx += 'WSc'; }; function lvff() { nslx += 'ld ='; }; function kri() { nslx += '= 0;'; }; fun" ascii
    $s7  = "ion mqi() { nslx += '; }'; }; function vuy() { nslx += '15'; }; function qyf() { nslx += '.Cre'; }; function pnf() { nslx += '.s" ascii
    $s8  = ") { '; }; function unzn() { nslx += 'ile'; }; function lvt() { nslx += '.Str'; }; function gzno() { nslx += 'qaran'; }; function" ascii
    $s9  = "{ nslx += 'kims'; }; function avy() { nslx += 'e();'; }; function bpkv() { nslx += ' i=l'; }; function fkfq() { nslx += '.Cre'; " ascii
    $s10 = " 'var '; }; function yyod() { nslx += '(); '; }; function zpz() { nslx += 'tStri'; }; var nslx = ''; function ika() { nslx += 'x" ascii
    $s11 = "nction jrjk() { nslx += 'Shel'; }; function fpo() { nslx += 'd('; }; function nqog() { nslx += 'ate'; }; function cnd() { nslx +" ascii
    $s12 = "= 'CharC'; }; function zsxs() { nslx += 'fn = '; }; function oyvn() { nslx += 'ch (e'; }; function sco() { nslx += '\"+'; }; fun" ascii
    $s13 = "va'; }; function mfy() { nslx += 'TTP\")'; }; function hih() { nslx += 'viro'; }; function hbrx() { nslx += 'DODB'; }; function " ascii
    $s14 = "; }; function tvwi() { nslx += '\"M'; }; function kfi() { nslx += 'eate'; }; function apdy() { nslx += 'L2.X'; }; function swa()" ascii
    $s15 = "; function xert() { nslx += ',2); '; }; function vcz() { nslx += 'd=7'; }; var tdoa = ''; function lkwb() { nslx += '?id'; }; fu" ascii
    $s16 = "i() { nslx += 'En'; }; function sis() { nslx += 'ount'; }; function xjw() { nslx += '== 20'; }; function jnq() { nslx += 'dy); '" ascii
    $s17 = "{ nslx += 'er/'; }; function smo() { nslx += 'respo'; }; function kbu() { nslx += ' for '; }; function ifht() { nslx += 'y.n'; }" ascii
    $s18 = " += 'n = '; }; function fhpp() { nslx += 'f (d'; }; function djvq() { vzvn += 'al'; };  function pua() { nslx += 'if ('; }; func" ascii
    $s19 = "tion kah() { nslx += ' }; i'; }; function ddt() { nslx += ' { w'; }; function uwxs() { nslx += 'l\"); '; }; function zef() { nsl" ascii
    $s20 = "unction viwr() { nslx += 'nd'; }; function zee() { nslx += 'ws.'; }; function yqwp() { nslx += ' }'; }; function vaqy() { nslx +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}