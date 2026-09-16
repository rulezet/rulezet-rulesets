rule TTP_XOR_QUAD_CurrentVersionRun_c9ca {
  strings:
    $key_c9ca = { 9a a5 [2] be ab [2] 95 87 [2] bb a5 [2] af be [2] a0 a4 [2] be b9 [2] bc b8 [2] a7 be [2] bb b9 [2] a7 96 }

  condition:
    any of them
}