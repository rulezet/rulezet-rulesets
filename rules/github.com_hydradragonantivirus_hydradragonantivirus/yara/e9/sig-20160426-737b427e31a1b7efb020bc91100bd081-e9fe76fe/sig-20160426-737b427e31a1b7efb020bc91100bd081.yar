rule sig_20160426_737b427e31a1b7efb020bc91100bd081 {
  meta:
    description = "datamaliciousorder - file 20160426_737b427e31a1b7efb020bc91100bd081.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de059e3b828fbd5498baf2d99188722a6d753a11b4b982e9046802566151b09e"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('17 229(349,114,37" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('17 229(349,114,37" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}