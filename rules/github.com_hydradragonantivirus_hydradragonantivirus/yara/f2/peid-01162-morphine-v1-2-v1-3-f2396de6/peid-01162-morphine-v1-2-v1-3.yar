rule PEiD_01162_Morphine_v1_2___v1_3_ {
  meta:
    description = "[Morphine v1.2 - v1.3]"
    ep_only     = "false"

  strings:
    $a = { FF 25 34 ?? 5A 00 8B C0 FF 25 38 ?? 5A 00 8B C0 }

  condition:
    $a
}