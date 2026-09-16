rule sig_20160422_26a9bb29494f926929e46b313651d038 {
  meta:
    description = "datamaliciousorder - file 20160422_26a9bb29494f926929e46b313651d038.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02d20321629c6902e194617ca1e58550961f8c39314c9ea983ea99bb4995cb84"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 2L(){8 42=\"8e\";b(42==f){8 41=8f;41=8h/8c;8 43=" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}