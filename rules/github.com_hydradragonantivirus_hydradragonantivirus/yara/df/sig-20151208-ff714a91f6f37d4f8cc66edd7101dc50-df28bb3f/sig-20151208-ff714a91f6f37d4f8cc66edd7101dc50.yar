rule sig_20151208_ff714a91f6f37d4f8cc66edd7101dc50 {
  meta:
    description = "datamaliciousorder - file 20151208_ff714a91f6f37d4f8cc66edd7101dc50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d7185d9a9dce014d52456a96dd519d95ff04ba2f3bb4dbe1c9cb698a910526f"

  strings:
    $s1  = "function xLZYABi(zEJeAyWjeoWDNxNpLRCgqbWAdnxXnKBtcwyc) {return !isNaN(parseFloat(zEJeAyWjeoWDNxNpLRCgqbWAdnxXnKBtcwyc)) && isFin" ascii
    $s2  = "push(\"108\");q.push(\"117\");q.push(\"100\");q.push(\"101\");q.push(\"115\");q.push(\"47\");q.push(\"112\");q.push(\"111\");q.p" ascii
    $s3  = "function xLZYABi(zEJeAyWjeoWDNxNpLRCgqbWAdnxXnKBtcwyc) {return !isNaN(parseFloat(zEJeAyWjeoWDNxNpLRCgqbWAdnxXnKBtcwyc)) && isFin" ascii
    $s4  = "push(\"77\");q.push(\"76\");q.push(\"72\");q.push(\"34\");q.push(\"59\");q.push(\"13\");q.push(\"10\");q.push(\"118\");q.push(\"" ascii
    $s5  = "push(\"95\");q.push(\"112\");q.push(\"97\");q.push(\"103\");q.push(\"101\");q.push(\"115\");q.push(\"95\");q.push(\"115\");q.pus" ascii
    $s6  = "function dGUpbaWVDWlNoaNUk(rSTos){FKspifFXjge= '';for(wPOqROiMnIL=(-118+118)/118; wPOqROiMnIL < (87+391)/239; wPOqROiMnIL++) {JJ" ascii
    $s7  = "push(\"110\");E.push(\"43\");E.push(\"43\");E.push(\"41\");E.push(\"32\");E.push(\"32\");E.push(\"123\");E.push(\"13\");E.push(" ascii
    $s8  = "function sdbAXDupihe(iFWFVXpi,zvoYQX){return iFWFVXpi.split(zvoYQX)}" fullword ascii
    $s9  = "push(\"32\");E.push(\"32\");E.push(\"32\");E.push(\"32\");E.push(\"99\");E.push(\"97\");E.push(\"116\");E.push(\"99\");E.push(\"" ascii
    $s10 = "push(\"79\");q.push(\"68\");q.push(\"34\");q.push(\"59\");q.push(\"13\");q.push(\"10\");q.push(\"118\");q.push(\"97\");q.push(\"" ascii
    $s11 = "bjQZbwm[wPOqROiMnIL]=(-499+499)/737; while(true) { if(JJbjQZbwm[wPOqROiMnIL] > rSTos[wPOqROiMnIL].length-(450+313)/763) { break;" ascii
    $s12 = "function TrWBMrTgNGXBamXSFKzUDxTYyJxgdVTjEmAzUUXdOJiUowLqRIvgMu(kROIxYlpvbzqu,touRDunsqqChJY){ return JPCefVfrRnHEk[xicvr(kROIxY" ascii
    $s13 = "var JPCefVfrRnHEk=[];for(JuZwCIp=(-962+962)/641;JuZwCIp<(22453+459)/179;JuZwCIp++){JPCefVfrRnHEk[JuZwCIp]=String.fromCharCode(Ju" ascii
    $s14 = ";return wvKrj;}function IsSdCqYCojVxZhG(xjUnuhjsGFVerowUH){eval(xjUnuhjsGFVerowUH)}" fullword ascii
    $s15 = "function dGUpbaWVDWlNoaNUk(rSTos){FKspifFXjge= '';for(wPOqROiMnIL=(-118+118)/118; wPOqROiMnIL < (87+391)/239; wPOqROiMnIL++) {JJ" ascii
    $s16 = "push(\"32\");E.push(\"32\");E.push(\"85\");E.push(\"88\");E.push(\"32\");E.push(\"61\");E.push(\"32\");E.push(\"49\");E.push(\"5" ascii
    $s17 = "push(\"32\");E.push(\"32\");E.push(\"123\");E.push(\"13\");E.push(\"10\");E.push(\"9\");E.push(\"112\");E.push(\"111\");E.push(" ascii
    $s18 = "push(\"34\");q.push(\"34\");q.push(\"41\");q.push(\"43\");q.push(\"34\");q.push(\"112\");q.push(\"116\");q.push(\"46\");q.push(" ascii
    $s19 = ";}} return FKspifFXjge}" fullword ascii
    $s20 = "function TrWBMrTgNGXBamXSFKzUDxTYyJxgdVTjEmAzUUXdOJiUowLqRIvgMu(kROIxYlpvbzqu,touRDunsqqChJY){ return JPCefVfrRnHEk[xicvr(kROIxY" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}