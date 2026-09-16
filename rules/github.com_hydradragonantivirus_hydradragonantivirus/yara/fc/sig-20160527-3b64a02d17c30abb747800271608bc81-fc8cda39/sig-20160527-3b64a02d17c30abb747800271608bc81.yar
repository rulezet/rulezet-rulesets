rule sig_20160527_3b64a02d17c30abb747800271608bc81 {
  meta:
    description = "datamaliciousorder - file 20160527_3b64a02d17c30abb747800271608bc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14808f5f455b1243e399cd8e0949891d711adb1dca22ab6d61d166b1d7025971"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ajaiTZCET.length;i++)if(i%2==0)x.push(ajaiTZCET[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}