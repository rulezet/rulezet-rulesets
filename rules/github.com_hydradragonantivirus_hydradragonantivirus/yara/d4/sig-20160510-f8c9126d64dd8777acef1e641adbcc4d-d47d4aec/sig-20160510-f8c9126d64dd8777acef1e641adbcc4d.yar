rule sig_20160510_f8c9126d64dd8777acef1e641adbcc4d {
  meta:
    description = "datamaliciousorder - file 20160510_f8c9126d64dd8777acef1e641adbcc4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acdec163526bdeb0ca05fba2e0b10909743b67d9e4a997b54f53fb8536eaf2ef"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('a F(U,46){if(\"\".l<=9V){4 9W=7(9U,8)}6{4 G=\"\"}4" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}