rule sig_20160527_9e5ff430306705d72b0b05d698b5a339 {
  meta:
    description = "datamaliciousorder - file 20160527_9e5ff430306705d72b0b05d698b5a339.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "339fbb5f6589647bce76f23ff384b11be739bbd18aa1cfdbd21978fb79484304"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aHpg1BYS.length;i++)if(i%2==0)x.push(aHpg1BYS[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}