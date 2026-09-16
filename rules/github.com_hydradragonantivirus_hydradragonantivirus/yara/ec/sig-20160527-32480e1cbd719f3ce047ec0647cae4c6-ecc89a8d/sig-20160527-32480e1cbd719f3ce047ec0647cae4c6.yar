rule sig_20160527_32480e1cbd719f3ce047ec0647cae4c6 {
  meta:
    description = "datamaliciousorder - file 20160527_32480e1cbd719f3ce047ec0647cae4c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c4aa72cbabc1fd6ebd5f2e44b3bf1d344933b0864a136f6a471d49def27d425"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ayUM1EuJ.length;i++)if(i%2==0)x.push(ayUM1EuJ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}