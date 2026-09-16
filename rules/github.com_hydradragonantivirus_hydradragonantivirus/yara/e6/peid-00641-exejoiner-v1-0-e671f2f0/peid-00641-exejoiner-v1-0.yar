rule PEiD_00641_EXEJoiner_v1_0_ {
  meta:
    description = "[EXEJoiner v1.0]"
    ep_only     = "true"

  strings:
    $a = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8 }

  condition:
    $a
}