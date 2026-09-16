rule PEiD_02474_UPXShit_0_06_ {
  meta:
    description = "[UPXShit 0.06]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }

  condition:
    $a
}