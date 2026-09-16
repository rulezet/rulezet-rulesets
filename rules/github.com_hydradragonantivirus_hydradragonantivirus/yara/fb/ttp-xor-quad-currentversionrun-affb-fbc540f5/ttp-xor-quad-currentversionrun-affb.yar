rule TTP_XOR_QUAD_CurrentVersionRun_affb {
  strings:
    $key_affb = { fc 94 [2] d8 9a [2] f3 b6 [2] dd 94 [2] c9 8f [2] c6 95 [2] d8 88 [2] da 89 [2] c1 8f [2] dd 88 [2] c1 a7 }

  condition:
    any of them
}