rule PEiD_02462_UPX_Scrambler_RC_v1_x_ {
  meta:
    description = "[UPX-Scrambler RC v1.x]"
    ep_only     = "true"

  strings:
    $a = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

  condition:
    $a
}