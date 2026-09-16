rule sig_20160510_27e0d1b94363a754eaa7c8f6cf062181 {
  meta:
    description = "datamaliciousorder - file 20160510_27e0d1b94363a754eaa7c8f6cf062181.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8260ad5ecfa8e4e51a1d5b403948ee86deb727d69a010991de2079286025abdd"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('j 2P(){4 4q=\"6Z\";if(4q!=\"\\\\I\\\\v\\\\z\\\\f" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}