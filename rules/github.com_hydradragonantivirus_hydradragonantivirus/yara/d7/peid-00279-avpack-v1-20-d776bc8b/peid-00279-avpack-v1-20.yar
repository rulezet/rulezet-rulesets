rule PEiD_00279_AVPACK_v1_20_ {
  meta:
    description = "[AVPACK v1.20]"
    ep_only     = "true"

  strings:
    $a = { 50 1E 0E 1F 16 07 33 F6 8B FE B9 ?? ?? FC F3 A5 06 BB ?? ?? 53 CB }

  condition:
    $a
}