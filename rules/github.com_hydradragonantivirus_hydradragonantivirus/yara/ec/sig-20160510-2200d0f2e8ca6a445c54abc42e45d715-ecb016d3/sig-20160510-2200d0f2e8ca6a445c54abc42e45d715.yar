rule sig_20160510_2200d0f2e8ca6a445c54abc42e45d715 {
  meta:
    description = "datamaliciousorder - file 20160510_2200d0f2e8ca6a445c54abc42e45d715.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18b0c5e3e079c1e6db42ecafcb8f912bd4362a00b0c13b3491175dcf654bbc0e"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('o kH(l,hH){o h(45){p 6.4C(45)}if(\"-9F\".i>=9G){9E" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}