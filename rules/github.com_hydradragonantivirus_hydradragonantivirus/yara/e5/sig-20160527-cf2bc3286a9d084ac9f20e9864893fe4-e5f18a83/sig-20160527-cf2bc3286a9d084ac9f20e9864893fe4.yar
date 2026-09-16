rule sig_20160527_cf2bc3286a9d084ac9f20e9864893fe4 {
  meta:
    description = "datamaliciousorder - file 20160527_cf2bc3286a9d084ac9f20e9864893fe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be1da398f3dc2f3602171730b51cdced2419a0080dae568b068f1f9621d2bfa4"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aMw198Mp.length;i++)if(i%2==0)x.push(aMw198Mp[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}