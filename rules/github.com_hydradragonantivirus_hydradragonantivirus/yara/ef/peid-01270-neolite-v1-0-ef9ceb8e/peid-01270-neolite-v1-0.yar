rule PEiD_01270_NeoLite_v1_0_ {
  meta:
    description = "[NeoLite v1.0]"
    ep_only     = "true"

  strings:
    $a = { E9 9B 00 00 00 A0 }

  condition:
    $a
}