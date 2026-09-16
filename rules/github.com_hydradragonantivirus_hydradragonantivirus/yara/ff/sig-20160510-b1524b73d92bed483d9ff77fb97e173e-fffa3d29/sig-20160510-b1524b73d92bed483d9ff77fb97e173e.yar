rule sig_20160510_b1524b73d92bed483d9ff77fb97e173e {
  meta:
    description = "datamaliciousorder - file 20160510_b1524b73d92bed483d9ff77fb97e173e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeb42214239232ad940efb56d2a8703c2c0c6c9514c89f50cb509367a4d2576d"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('f i(U){if(\"9g\".n(\"9h\")>0){4 9f=\"\\\\r\\\\11" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}