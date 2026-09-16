rule PEiD_02126_SoftSentry_v3_0_ {
  meta:
    description = "[SoftSentry v3.0]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06 }

  condition:
    $a
}