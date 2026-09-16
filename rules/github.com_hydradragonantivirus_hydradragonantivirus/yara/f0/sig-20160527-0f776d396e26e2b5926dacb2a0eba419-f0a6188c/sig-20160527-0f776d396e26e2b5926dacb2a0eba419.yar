rule sig_20160527_0f776d396e26e2b5926dacb2a0eba419 {
  meta:
    description = "datamaliciousorder - file 20160527_0f776d396e26e2b5926dacb2a0eba419.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed981fef9e82c11bc563ce78b2c48595d2763a0cbc5005eca6cbd9e2a01f64fb"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<am6LeXs.length;i++)if(i%2==0)x.push(am6LeXs[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}