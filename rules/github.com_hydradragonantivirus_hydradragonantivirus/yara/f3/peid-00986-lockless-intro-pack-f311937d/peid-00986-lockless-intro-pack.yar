rule PEiD_00986_Lockless_Intro_Pack_ {
  meta:
    description = "[Lockless Intro Pack]"
    ep_only     = "true"

  strings:
    $a = { 2C E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85 }

  condition:
    $a
}