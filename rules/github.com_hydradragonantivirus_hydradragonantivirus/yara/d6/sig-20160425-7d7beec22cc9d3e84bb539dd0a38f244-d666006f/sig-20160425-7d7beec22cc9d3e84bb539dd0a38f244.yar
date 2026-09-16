rule sig_20160425_7d7beec22cc9d3e84bb539dd0a38f244 {
  meta:
    description = "datamaliciousorder - file 20160425_7d7beec22cc9d3e84bb539dd0a38f244.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dacca4e4835cba4a60929ac39b893784388cccc87549c4175d32575d475a3cf1"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('21 317(173,495,49" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('21 317(173,495,49" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}