rule sig_20151208_3e265e1ed64341f61865492e319db1de {
  meta:
    description = "datamaliciousorder - file 20151208_3e265e1ed64341f61865492e319db1de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb8c67e410764a5ea0fe1b49308a17a4df9685ed80e6d4ee65bd1f380a5ad6ce"

  strings:
    $s1  = "function pFCWmAh(BZZzNwsEZBeUacBmXPjRNjncDOHUacYjRHdM) {return !isNaN(parseFloat(BZZzNwsEZBeUacBmXPjRNjncDOHUacYjRHdM)) && isFin" ascii
    $s2  = "function pFCWmAh(BZZzNwsEZBeUacBmXPjRNjncDOHUacYjRHdM) {return !isNaN(parseFloat(BZZzNwsEZBeUacBmXPjRNjncDOHUacYjRHdM)) && isFin" ascii
    $s3  = "push(\"41\");X.push(\"32\");X.push(\"32\");X.push(\"123\");X.push(\"32\");X.push(\"13\");X.push(\"10\");X.push(\"32\");X.push(\"" ascii
    $s4  = "LWK)}function SNbBT(pfiKVKxccWU,slEqFcBMqLyZj,TMZVJxVe){pnbz=parseInt(pfiKVKxccWU,slEqFcBMqLyZj);JXROM=pnbz.toString(TMZVJxVe);r" ascii
    $s5  = "function oszfaxigdhPhLThMA(epcmb){ZjBJPfLouPL= '';for(NVZIDIafbyS=(-404+404)/730; NVZIDIafbyS < (101+659)/380; NVZIDIafbyS++) {i" ascii
    $s6  = "function oszfaxigdhPhLThMA(epcmb){ZjBJPfLouPL= '';for(NVZIDIafbyS=(-404+404)/730; NVZIDIafbyS < (101+659)/380; NVZIDIafbyS++) {i" ascii
    $s7  = "push(\"13\");X.push(\"10\");X.push(\"32\");X.push(\"32\");X.push(\"32\");X.push(\"32\");X.push(\"32\");X.push(\"32\");X.push(\"8" ascii
    $s8  = "function yHlZIfamNzadxhnVvHQUXsEwYqxAZWNqwQahyZpMShWBqHGwvsgUuM(MaIYzFclYnpqX,FotNeciBhhCCtY){ return SCpZvapzSmmds[SNbBT(MaIYzF" ascii
    $s9  = ";}} return ZjBJPfLouPL}" fullword ascii
    $s10 = "push(\"32\");X.push(\"50\");X.push(\"51\");X.push(\"50\");X.push(\"48\");X.push(\"45\");X.push(\"55\");X.push(\"50\");X.push(\"5" ascii
    $s11 = "function yHlZIfamNzadxhnVvHQUXsEwYqxAZWNqwQahyZpMShWBqHGwvsgUuM(MaIYzFclYnpqX,FotNeciBhhCCtY){ return SCpZvapzSmmds[SNbBT(MaIYzF" ascii
    $s12 = "function rgokIoHAlqi(ojTFlTUv,AUUKTI){return ojTFlTUv.split(AUUKTI)}" fullword ascii
    $s13 = "push(\"32\");B.push(\"34\");B.push(\"84\");B.push(\"84\");B.push(\"80\");B.push(\"34\");B.push(\"59\");B.push(\"13\");B.push(\"1" ascii
    $s14 = "push(\"87\");B.push(\"83\");B.push(\"99\");B.push(\"114\");B.push(\"105\");B.push(\"34\");B.push(\"58\");B.push(\"34\");B.push(" ascii
    $s15 = "push(\"100\");X.push(\"121\");X.push(\"41\");X.push(\"59\");X.push(\"32\");X.push(\"105\");X.push(\"102\");X.push(\"32\");X.push" ascii
    $s16 = "var SCpZvapzSmmds=[];for(jDknLWK=(-13+13)/205;jDknLWK<(34068+108)/267;jDknLWK++){SCpZvapzSmmds[jDknLWK]=String.fromCharCode(jDkn" ascii
    $s17 = "qzGlIjlG[NVZIDIafbyS]=(-649+649)/454; while(true) { if(iqzGlIjlG[NVZIDIafbyS] > epcmb[NVZIDIafbyS].length-(-142+863)/721) { brea" ascii
    $s18 = "push(\"10\");X.push(\"9\");X.push(\"9\");X.push(\"125\");X.push(\"13\");X.push(\"10\");X.push(\"32\");X.push(\"32\");X.push(\"32" ascii
    $s19 = "eturn JXROM;}function yyuWiwGaereoBIc(WfSdxBRsVGpJHOaQN){eval(WfSdxBRsVGpJHOaQN)}" fullword ascii
    $s20 = "push(\"47\");B.push(\"42\");B.push(\"79\");B.push(\"112\");B.push(\"88\");B.push(\"68\");B.push(\"57\");B.push(\"49\");B.push(\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}