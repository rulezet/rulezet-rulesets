rule sig_20160512_30af2986a68ee3a5765674c9494f7fa7 {
  meta:
    description = "datamaliciousorder - file 20160512_30af2986a68ee3a5765674c9494f7fa7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e8c6e5b8cceec46ca03ea8cd12d1eeef55b5864a20c05c05e63ac3fbd5b5f91"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('4 29(){3 1S=\"f\";5 1S}4 u(){3 1R=\"r\";5 1R}4 F()" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}