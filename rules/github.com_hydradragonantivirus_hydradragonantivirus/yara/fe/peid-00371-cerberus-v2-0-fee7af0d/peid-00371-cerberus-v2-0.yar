rule PEiD_00371_CERBERUS_v2_0_ {
  meta:
    description = "[CERBERUS v2.0]"
    ep_only     = "true"

  strings:
    $a = { 9C 2B ED 8C ?? ?? 8C ?? ?? FA E4 ?? 88 ?? ?? 16 07 BF ?? ?? 8E DD 9B F5 B9 ?? ?? FC F3 A5 }

  condition:
    $a
}