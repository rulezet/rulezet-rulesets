rule sig_20160527_98de085493d27349c732b251b1e14320 {
  meta:
    description = "datamaliciousorder - file 20160527_98de085493d27349c732b251b1e14320.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc0b9ed3896fbc36c07543079f2dcf47810ccea86ecd1721ebec22cd6c46d1b7"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<amyp391qW.length;i++)if(i%2==0)x.push(amyp391qW[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}