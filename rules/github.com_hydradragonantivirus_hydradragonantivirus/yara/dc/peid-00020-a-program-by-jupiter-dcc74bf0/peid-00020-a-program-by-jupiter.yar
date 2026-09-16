rule PEiD_00020_A_program_by_Jupiter____ {
  meta:
    description = "[A program by Jupiter ..]"
    ep_only     = "true"

  strings:
    $a = { 2B C0 74 05 68 ?? ?? ?? ?? 50 }

  condition:
    $a
}