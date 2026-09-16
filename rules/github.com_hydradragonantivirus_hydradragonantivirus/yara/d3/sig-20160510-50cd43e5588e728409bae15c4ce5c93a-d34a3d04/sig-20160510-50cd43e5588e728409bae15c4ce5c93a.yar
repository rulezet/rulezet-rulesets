rule sig_20160510_50cd43e5588e728409bae15c4ce5c93a {
  meta:
    description = "datamaliciousorder - file 20160510_50cd43e5588e728409bae15c4ce5c93a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3c58e2f68b53871dbc327b4326673b60fae7dac86684d14d2ba7838ca1fb520"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('e 1c(4j){4 4C=-1;if(6.t(4C)==0){9r=\"\"}5{9s=-9q}i" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}