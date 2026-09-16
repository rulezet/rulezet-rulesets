rule sig_20160510_37c0d6079ac6d401c8e4780059354681 {
  meta:
    description = "datamaliciousorder - file 20160510_37c0d6079ac6d401c8e4780059354681.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "975b66cd6c2242e56a8efe83e371e39401f1e1d99d47006499f823c3b5e5a81e"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('f 9F(g,3Q){4 E=\"9G\";4 4h=\"\";if(E==4h){9H=-9E}6" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}