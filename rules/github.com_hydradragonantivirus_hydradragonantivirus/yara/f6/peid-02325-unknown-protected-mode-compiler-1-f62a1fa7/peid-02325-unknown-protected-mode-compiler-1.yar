rule PEiD_02325_Unknown_Protected_Mode_compiler__1__ {
  meta:
    description = "[Unknown Protected Mode compiler (1)]"
    ep_only     = "true"

  strings:
    $a = { FA BC ?? ?? 8C C8 8E D8 E8 ?? ?? E8 ?? ?? E8 ?? ?? 66 B8 ?? ?? ?? ?? 66 C1 }

  condition:
    $a
}