rule PEiD_00365_CC_v2_61_Beta_ {
  meta:
    description = "[CC v2.61 Beta]"
    ep_only     = "true"

  strings:
    $a = { BA ?? ?? B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB }

  condition:
    $a
}