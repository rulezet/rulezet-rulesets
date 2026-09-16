rule sig_20160527_430d314169e5c7d05b384d8b5281a0d8 {
  meta:
    description = "datamaliciousorder - file 20160527_430d314169e5c7d05b384d8b5281a0d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d70de1db7405e4a0f9554e9dc1f80268c7c33c5dd1e9c9f72253fc70685ff423"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ansZAd.length;i++)if(i%2==0)x.push(ansZAd[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}