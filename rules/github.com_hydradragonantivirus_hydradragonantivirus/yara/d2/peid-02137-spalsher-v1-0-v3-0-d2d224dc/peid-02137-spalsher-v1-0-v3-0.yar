rule PEiD_02137_Spalsher_v1_0___v3_0_ {
  meta:
    description = "[Spalsher v1.0 - v3.0]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84 }

  condition:
    $a
}