rule sig_20160527_29e11a312d45d394fc9751d9b6c05f82 {
  meta:
    description = "datamaliciousorder - file 20160527_29e11a312d45d394fc9751d9b6c05f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72da777979cec47b748918ea3c00763edd6079d3c9256dcb1fabd0276db387c3"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<awQVgVdyPq5.length;i++)if(i%2==0)x.push(awQVgVdyPq5[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}