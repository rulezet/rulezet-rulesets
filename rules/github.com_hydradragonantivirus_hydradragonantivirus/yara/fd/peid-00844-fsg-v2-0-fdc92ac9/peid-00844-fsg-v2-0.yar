rule PEiD_00844_FSG_v2_0_ {
  meta:
    description = "[FSG v2.0]"
    ep_only     = "false"

  strings:
    $a = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 }

  condition:
    $a
}