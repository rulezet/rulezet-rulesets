rule PEiD_02292_Turbo_C_1988_ {
  meta:
    description = "[Turbo C 1988]"
    ep_only     = "true"

  strings:
    $a = { 8C D8 BB ?? ?? 8E DB 8C D3 8B CC FA 8E ?? ?? ?? BC }

  condition:
    $a
}