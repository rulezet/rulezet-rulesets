rule PEiD_03499_X_PEOR_v0_99b_ {
  meta:
    description = "[X-PEOR v0.99b]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }

  condition:
    $a
}