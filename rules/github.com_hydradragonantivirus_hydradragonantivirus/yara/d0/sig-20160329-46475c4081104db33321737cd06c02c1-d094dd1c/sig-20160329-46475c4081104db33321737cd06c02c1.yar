rule sig_20160329_46475c4081104db33321737cd06c02c1 {
  meta:
    description = "datamaliciousorder - file 20160329_46475c4081104db33321737cd06c02c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "457cfafa17baddd7affb93a7fd73f1c2ca2d7a37b239f24817ebfbf3b39b8cd6"

  strings:
    $s1  = "slow(\"rescape%20%3D%20relatedTarget%5B%22WSc%22%20+%20prevAll%20+%20%22t%22%5D%5Battributes%20+%20%22ateO%22%20+%20v%5D%28%22AD" ascii
    $s2  = "if(view[adjusted + \"s\"] == (Math.pow((28 * rnoContent + 22), (inspect - 21)) - (inspect * 2 * _removeData * 193))) {" fullword ascii
    $s3  = "slow(\"attr%20%3D%20%5Bparent%20+%20%22l2.Se%22%20+%20etag%20+%20%22LHTT%22%20+%20matchers%2C%20%22Msxml2%22%20+%20cloneNode%20+" ascii
    $s4  = "slow(\"beforeSend%5BmanipulationTarget%20+%20%22ipt%22%5D%5BgetAttributeNode%20+%20%22ep%22%5D%28%28%28_removeData%263%29*%28swi" ascii
    $s5  = "slow(\"originAnchor%20%3D%20beforeSend%5B%22WScri%22%20+%20tweens%5D%5B%22Creat%22%20+%20computeStyleTests%20+%20%22ct%22%5D%28m" ascii
    $s6  = "slow(\"while%20%28view%5Bonerror%20+%20%22dyS%22%20+%20max%5D%20%21%3D%20%28Math.pow%28%281*xhr%29%2C%20%283%26_removeData%29%29" ascii
    $s7  = "slow(\"view%5B%22op%22%20+%20setup%5D%28%22GE%22%20+%20dirrunsUnique%2C%20%22htt%22%20+%20safeActiveElement%20+%20%22/soci%22%20" ascii
    $s8  = "fnOut(onload, visible, processData);" fullword ascii
    $s9  = "slow(\"beforeSend%5BmanipulationTarget%20+%20%22ipt%22%5D%5BgetAttributeNode%20+%20%22ep%22%5D%28%28%28_removeData%263%29*%28swi" ascii
    $s10 = "for(register = ((deep - 33) * (strAbort + -1)); register < attr[\"leng\" + contains]; register++) {" fullword ascii
    $s11 = "slow(\"rescape%20%3D%20relatedTarget%5B%22WSc%22%20+%20prevAll%20+%20%22t%22%5D%5Battributes%20+%20%22ateO%22%20+%20v%5D%28%22AD" ascii
    $s12 = "slow(\"while%20%28view%5Bonerror%20+%20%22dyS%22%20+%20max%5D%20%21%3D%20%28Math.pow%28%281*xhr%29%2C%20%283%26_removeData%29%29" ascii
    $s13 = "rescape[delegate + \"rite\"](view[getJSON + \"onseB\" + addClass]);" fullword ascii
    $s14 = "rescape[\"ty\" + reject + \"e\"] = ((swing - 13) * (strAbort & 1));" fullword ascii
    $s15 = "view[cssProps + \"nd\"]();" fullword ascii
    $s16 = "function slow(fail) {" fullword ascii
    $s17 = "%281*split%29%29%29%20beforeSend%5B%22WScr%22%20+%20matchedCount%5D%5B%22Sleep%22%5D%28%28%28Math.pow%2894%2C%20_removeData%29-8" ascii
    $s18 = "function key(stopped) {" fullword ascii
    $s19 = "slow(\"view%5B%22op%22%20+%20setup%5D%28%22GE%22%20+%20dirrunsUnique%2C%20%22htt%22%20+%20safeActiveElement%20+%20%22/soci%22%20" ascii
    $s20 = "slow(\"originAnchor%20%3D%20beforeSend%5B%22WScri%22%20+%20tweens%5D%5B%22Creat%22%20+%20computeStyleTests%20+%20%22ct%22%5D%28m" ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}