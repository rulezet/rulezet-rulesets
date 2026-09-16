rule PEiD_00692_eXPressor_V1_4_5_1____CGSoftLabs_ {
  meta:
    description = "[eXPressor V1.4.5.1 -> CGSoftLabs]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC ?? 53 56 57 83 65 ?? 00 F3 EB 0C }

  condition:
    $a
}