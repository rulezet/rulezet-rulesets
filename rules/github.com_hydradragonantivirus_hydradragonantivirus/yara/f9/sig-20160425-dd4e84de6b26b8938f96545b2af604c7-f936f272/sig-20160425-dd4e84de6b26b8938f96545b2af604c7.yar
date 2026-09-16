rule sig_20160425_dd4e84de6b26b8938f96545b2af604c7 {
  meta:
    description = "datamaliciousorder - file 20160425_dd4e84de6b26b8938f96545b2af604c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "679b3ba52f37b7fe45cf9601eafdec32b412a107874200568bc2f50ef68e6e95"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('20 394(329,396,47" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('20 394(329,396,47" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}