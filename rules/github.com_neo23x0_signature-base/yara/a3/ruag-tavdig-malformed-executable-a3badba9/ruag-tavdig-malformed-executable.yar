rule RUAG_Tavdig_Malformed_Executable {
  meta:
    description = "Detects an embedded executable with a malformed header - known from Tavdig malware"
    author = "Florian Roth (Nextron Systems)"
    reference = "https://goo.gl/N5MEj0"
    score = 60
    id = "da6357d4-0cdb-5f30-9919-59858963cc41"
  condition:
    uint16(0) == 0x5a4d and 
    uint32(uint32(0x3C)) == 0x0000AD0B 
}