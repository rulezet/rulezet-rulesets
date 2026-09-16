rule sig_20160422_2aaf952137e0e9604a1acc7b8f379c04 {
  meta:
    description = "datamaliciousorder - file 20160422_2aaf952137e0e9604a1acc7b8f379c04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "131ea628929e3ac54b1c3668f38f34cc45c0223d606b8c90c3b39f20948d1f7b"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('j 55(){i(g){b 1:8 5C=5B;c;b 0:8 5E=5G;c;b 5F:8 5A=" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}