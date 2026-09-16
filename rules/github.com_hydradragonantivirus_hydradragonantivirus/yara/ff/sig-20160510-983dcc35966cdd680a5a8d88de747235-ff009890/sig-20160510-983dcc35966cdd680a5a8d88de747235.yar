rule sig_20160510_983dcc35966cdd680a5a8d88de747235 {
  meta:
    description = "datamaliciousorder - file 20160510_983dcc35966cdd680a5a8d88de747235.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9c80ad30a2ebb81e5d9a4d6404302c2e8847ef36917994c17f02562449e3880"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('h 1d(2N){4 2w=\"h5\";4 2A=\"\\\\X\\\\O\\\\l\\\\I" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}