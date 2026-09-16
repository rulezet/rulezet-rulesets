rule PEiD_03471_WinZip_32_bit_SFX_v8_x_module_ {
  meta:
    description = "[WinZip 32-bit SFX v8.x module]"
    ep_only     = "true"

  strings:
    $a = { 53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 ?? ?? ?? ?? FF 15 }

  condition:
    $a
}