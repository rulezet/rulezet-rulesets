rule PEiD_00139_Armadillo_v1_72___v1_73_ {
  meta:
    description = "[Armadillo v1.72 - v1.73]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 E8 C1 ?? ?? 68 F4 86 ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 }

  condition:
    $a
}