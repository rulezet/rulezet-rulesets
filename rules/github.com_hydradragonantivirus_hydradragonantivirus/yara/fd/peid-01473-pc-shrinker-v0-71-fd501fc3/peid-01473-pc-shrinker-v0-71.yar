rule PEiD_01473_PC_Shrinker_v0_71_ {
  meta:
    description = "[PC Shrinker v0.71]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85 }

  condition:
    $a
}