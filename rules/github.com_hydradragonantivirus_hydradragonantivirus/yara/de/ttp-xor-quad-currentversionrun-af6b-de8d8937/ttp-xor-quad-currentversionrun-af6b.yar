rule TTP_XOR_QUAD_CurrentVersionRun_af6b {
  strings:
    $key_af6b = { fc 04 [2] d8 0a [2] f3 26 [2] dd 04 [2] c9 1f [2] c6 05 [2] d8 18 [2] da 19 [2] c1 1f [2] dd 18 [2] c1 37 }

  condition:
    any of them
}