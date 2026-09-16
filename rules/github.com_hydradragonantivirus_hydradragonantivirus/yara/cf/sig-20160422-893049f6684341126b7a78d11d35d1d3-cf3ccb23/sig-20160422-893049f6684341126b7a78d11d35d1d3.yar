rule sig_20160422_893049f6684341126b7a78d11d35d1d3 {
  meta:
    description = "datamaliciousorder - file 20160422_893049f6684341126b7a78d11d35d1d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e976f76a923dd01c286d40b3f32ad1744bb8713cad469625fbc06ff96b43da9"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('l 4F(59,1k){g(\"7c\"){9 1:8 7b=\"7a\";b;9 5h:c(1k=" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}