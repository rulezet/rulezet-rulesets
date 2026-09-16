rule sig_20160510_d65392471425c84ba8cf5009a4ef9937 {
  meta:
    description = "datamaliciousorder - file 20160510_d65392471425c84ba8cf5009a4ef9937.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ccef32060cd7b37c9356354184731dba4521da41955ad544db20ee31a6fd03d"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('7 2a(Z,14){if(\"-9r\".g==-9s){9q=\"-9p\"}6{4 9m=" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}