import "pe"
rule MicroJoiner_1_5____coban2k {
  strings:
    $a0 = { BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF }

  condition:
    $a0 at pe.entry_point
}