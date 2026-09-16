rule PEiD_03556_Zortech_C_ {
  meta:
    description = "[Zortech C]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 2E FF ?? ?? ?? FC 06 }

  condition:
    $a
}