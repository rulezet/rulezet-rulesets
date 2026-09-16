rule sig_20160527_090022547bc90cceb6aa815c98947a9d {
  meta:
    description = "datamaliciousorder - file 20160527_090022547bc90cceb6aa815c98947a9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a70f4b9276ecbb2f050a8bc16e715e396f270080beedc02c411498bf64828d8"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a3Iw7S6Y.length;i++)if(i%2==0)x.push(a3Iw7S6Y[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}