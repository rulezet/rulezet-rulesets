rule TTP_XOR_QUAD_CurrentVersionRun_c99b {
  strings:
    $key_c99b = { 9a f4 [2] be fa [2] 95 d6 [2] bb f4 [2] af ef [2] a0 f5 [2] be e8 [2] bc e9 [2] a7 ef [2] bb e8 [2] a7 c7 }

  condition:
    any of them
}