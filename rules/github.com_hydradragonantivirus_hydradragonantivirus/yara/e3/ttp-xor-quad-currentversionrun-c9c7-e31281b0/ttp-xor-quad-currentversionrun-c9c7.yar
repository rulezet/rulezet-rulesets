rule TTP_XOR_QUAD_CurrentVersionRun_c9c7 {
  strings:
    $key_c9c7 = { 9a a8 [2] be a6 [2] 95 8a [2] bb a8 [2] af b3 [2] a0 a9 [2] be b4 [2] bc b5 [2] a7 b3 [2] bb b4 [2] a7 9b }

  condition:
    any of them
}