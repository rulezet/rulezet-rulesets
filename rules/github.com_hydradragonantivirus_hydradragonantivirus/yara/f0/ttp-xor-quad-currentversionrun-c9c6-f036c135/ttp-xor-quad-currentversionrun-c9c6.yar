rule TTP_XOR_QUAD_CurrentVersionRun_c9c6 {
  strings:
    $key_c9c6 = { 9a a9 [2] be a7 [2] 95 8b [2] bb a9 [2] af b2 [2] a0 a8 [2] be b5 [2] bc b4 [2] a7 b2 [2] bb b5 [2] a7 9a }

  condition:
    any of them
}