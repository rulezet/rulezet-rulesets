rule PEiD_03374_Vx__Compiler_ {
  meta:
    description = "[Vx: Compiler]"
    ep_only     = "true"

  strings:
    $a = { 8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E }

  condition:
    $a
}