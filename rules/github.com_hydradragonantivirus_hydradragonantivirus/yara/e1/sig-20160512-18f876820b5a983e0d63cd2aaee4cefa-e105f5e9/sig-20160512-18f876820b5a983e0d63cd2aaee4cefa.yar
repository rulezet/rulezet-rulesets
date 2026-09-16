rule sig_20160512_18f876820b5a983e0d63cd2aaee4cefa {
  meta:
    description = "datamaliciousorder - file 20160512_18f876820b5a983e0d63cd2aaee4cefa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8945fd5595a6287f96c266025f356ba305ce1d09df79d3da76a95e5cfb05cecd"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('4 2b(){3 1N=\"f\";5 1N}4 p(){3 1M=\"r\";5 1M}4 w()" ascii
    $s3 = "split('|'),0,{}))" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}