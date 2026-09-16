rule PEiD_01769_Private_EXE_v2_0a_ {
  meta:
    description = "[Private EXE v2.0a]"
    ep_only     = "false"

  strings:
    $a = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D }

  condition:
    $a
}