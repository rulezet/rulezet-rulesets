rule PEiD_01455_PassLock_2000_v1_0__Eng_____Moonlight_Software_ {
  meta:
    description = "[PassLock 2000 v1.0 (Eng) -> Moonlight-Software]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 }

  condition:
    $a
}