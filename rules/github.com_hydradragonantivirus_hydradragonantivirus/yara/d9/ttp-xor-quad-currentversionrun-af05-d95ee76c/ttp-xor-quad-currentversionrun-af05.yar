rule TTP_XOR_QUAD_CurrentVersionRun_af05 {
  strings:
    $key_af05 = { fc 6a [2] d8 64 [2] f3 48 [2] dd 6a [2] c9 71 [2] c6 6b [2] d8 76 [2] da 77 [2] c1 71 [2] dd 76 [2] c1 59 }

  condition:
    any of them
}