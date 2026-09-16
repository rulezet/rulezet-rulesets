rule sig_20160527_f49a8f23998cbc4cdbb7becf15b1bfca {
  meta:
    description = "datamaliciousorder - file 20160527_f49a8f23998cbc4cdbb7becf15b1bfca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc1438f0df82bb9f02b754f5b5afcab35e510278183477684f3e5543dae95388"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<atdwZHco15.length;i++)if(i%2==0)x.push(atdwZHco15[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}