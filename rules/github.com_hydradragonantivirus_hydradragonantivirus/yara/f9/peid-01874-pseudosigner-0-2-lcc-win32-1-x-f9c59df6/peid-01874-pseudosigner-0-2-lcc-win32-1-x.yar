rule PEiD_01874_PseudoSigner_0_2__LCC_Win32_1_x__ {
  meta:
    description = "[PseudoSigner 0.2 [LCC Win32 1.x]]"
    ep_only     = "true"

  strings:
    $a = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 }

  condition:
    $a
}