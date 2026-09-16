rule VirusShareBackDoorMeterpreter35 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorMeterpreter35.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b56056453ad84184b4714e4ea944cf8b576aabf0d671f9cfbc00fad52a1cdc68"

  strings:
    $s1 = "HeapAlloc error" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}