rule sig_20151208_64127962d211a468c8c915d511c5edea {
  meta:
    description = "datamaliciousorder - file 20151208_64127962d211a468c8c915d511c5edea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe84224e52fdccc2170652e2f9a8937c5bfeb887ba577c887669233754622aa6"

  strings:
    $s1  = "function COopiZr(KJIOGyYrPzAPTwzCWKhLxVLJwztsrdIgyfvD) {return !isNaN(parseFloat(KJIOGyYrPzAPTwzCWKhLxVLJwztsrdIgyfvD)) && isFin" ascii
    $s2  = "function COopiZr(KJIOGyYrPzAPTwzCWKhLxVLJwztsrdIgyfvD) {return !isNaN(parseFloat(KJIOGyYrPzAPTwzCWKhLxVLJwztsrdIgyfvD)) && isFin" ascii
    $s3  = "push(\"110\");s.push(\"89\");s.push(\"32\");s.push(\"61\");s.push(\"32\");s.push(\"65\");s.push(\"99\");s.push(\"75\");s.push(\"" ascii
    $s4  = "function ksGPTJXyBNLpSQfXe(kaemT){xxToTTjXQVn= '';for(VIhXinDPxvN=(-655+655)/751; VIhXinDPxvN < (-232+742)/255; VIhXinDPxvN++) {" ascii
    $s5  = "function lPAwgBunJJe(LRtJgKTG,FBzUyS){return LRtJgKTG.split(FBzUyS)}" fullword ascii
    $s6  = "++;}} return xxToTTjXQVn}" fullword ascii
    $s7  = "push(\"69\");s.push(\"120\");s.push(\"112\");s.push(\"97\");s.push(\"110\");s.push(\"100\");s.push(\"69\");s.push(\"110\");s.pus" ascii
    $s8  = "push(\"97\");E.push(\"107\");E.push(\"59\");E.push(\"32\");E.push(\"13\");E.push(\"10\");E.push(\"32\");E.push(\"32\");E.push(\"" ascii
    $s9  = "gufR)}function utlNp(imGIzityAan,auChWALzUwnOL,uqLUHUtO){hWGm=parseInt(imGIzityAan,auChWALzUwnOL);axsEk=hWGm.toString(uqLUHUtO);" ascii
    $s10 = "RudXbJdUr[VIhXinDPxvN]=(-545+545)/802; while(true) { if(RudXbJdUr[VIhXinDPxvN] > kaemT[VIhXinDPxvN].length-(578+331)/909) { brea" ascii
    $s11 = "var ooSdulIDqCHeu=[];for(hdbgufR=(-865+865)/1000;hdbgufR<(12603+69)/99;hdbgufR++){ooSdulIDqCHeu[hdbgufR]=String.fromCharCode(hdb" ascii
    $s12 = "push(\"47\");s.push(\"42\");s.push(\"90\");s.push(\"105\");s.push(\"109\");s.push(\"78\");s.push(\"51\");s.push(\"53\");s.push(" ascii
    $s13 = "push(\"32\");s.push(\"61\");s.push(\"32\");s.push(\"87\");s.push(\"83\");s.push(\"99\");s.push(\"114\");s.push(\"105\");s.push(" ascii
    $s14 = "function paikRxJxahgTdyLRyFdbxanlsLeLeLkRPNUnMmxXWGMjqAOqwNNvlX(djMgmSkyLIVdS,TUhyNhDdJfmwvg){ return ooSdulIDqCHeu[utlNp(djMgmS" ascii
    $s15 = "return axsEk;}function NXDBzfkfrolJjjD(UIactXgZIATPjsfje){eval(UIactXgZIATPjsfje)}" fullword ascii
    $s16 = "function ksGPTJXyBNLpSQfXe(kaemT){xxToTTjXQVn= '';for(VIhXinDPxvN=(-655+655)/751; VIhXinDPxvN < (-232+742)/255; VIhXinDPxvN++) {" ascii
    $s17 = "function paikRxJxahgTdyLRyFdbxanlsLeLeLkRPNUnMmxXWGMjqAOqwNNvlX(djMgmSkyLIVdS,TUhyNhDdJfmwvg){ return ooSdulIDqCHeu[utlNp(djMgmS" ascii
    $s18 = "push(\"59\");E.push(\"32\");E.push(\"119\");E.push(\"75\");E.push(\"113\");E.push(\"46\");E.push(\"112\");E.push(\"111\");E.push" ascii
    $s19 = "push(\"32\");s.push(\"61\");s.push(\"32\");s.push(\"52\");s.push(\"52\");s.push(\"48\");s.push(\"49\");s.push(\"50\");s.push(\"5" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}