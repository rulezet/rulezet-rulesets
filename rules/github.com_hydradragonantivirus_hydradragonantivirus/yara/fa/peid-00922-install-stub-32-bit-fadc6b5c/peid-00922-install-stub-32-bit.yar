rule PEiD_00922_Install_Stub_32_bit_ {
  meta:
    description = "[Install Stub 32-bit]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 29 }

  condition:
    $a
}