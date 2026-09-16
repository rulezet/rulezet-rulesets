rule sig_20160527_a2a1b95336077f384141408d23bb5b81 {
  meta:
    description = "datamaliciousorder - file 20160527_a2a1b95336077f384141408d23bb5b81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "287279e80bcfab789821a67482253f371988d62b6b598c7862ba6887023a553d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ahMXWh.length;i++)if(i%2==0)x.push(ahMXWh[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}