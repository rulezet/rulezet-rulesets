rule sig_20160527_0daf7f7bb59b48e469fde09f845299b6 {
  meta:
    description = "datamaliciousorder - file 20160527_0daf7f7bb59b48e469fde09f845299b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a9f8158434031db04de05e053099e9bed5a55fb1acd1cd805e87679a31f548a"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aJL9uC.length;i++)if(i%2==0)x.push(aJL9uC[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}