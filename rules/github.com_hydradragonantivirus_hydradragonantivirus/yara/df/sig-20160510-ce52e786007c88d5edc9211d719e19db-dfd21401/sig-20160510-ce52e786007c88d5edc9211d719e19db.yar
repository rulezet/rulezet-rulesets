rule sig_20160510_ce52e786007c88d5edc9211d719e19db {
  meta:
    description = "datamaliciousorder - file 20160510_ce52e786007c88d5edc9211d719e19db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a9fc3026ec85b1df5946478846bb2d22e165fcc7d590e2e81e99fc7e712f0ca"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('b 4b(){4 i=1;if(5.l(i)===0){ce=\\'\\\\1a\\\\Z\\\\1" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}