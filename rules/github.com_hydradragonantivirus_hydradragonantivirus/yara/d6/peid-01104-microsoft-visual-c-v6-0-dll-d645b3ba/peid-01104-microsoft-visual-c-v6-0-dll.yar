rule PEiD_01104_Microsoft_Visual_C___v6_0_DLL_ {
  meta:
    description = "[Microsoft Visual C++ v6.0 DLL]"
    ep_only     = "true"

  strings:
    $a = { 55 8D 6C ?? ?? 81 EC ?? ?? ?? ?? 8B 45 ?? 83 F8 01 56 0F 84 ?? ?? ?? ?? 85 C0 0F 84 }

  condition:
    $a
}