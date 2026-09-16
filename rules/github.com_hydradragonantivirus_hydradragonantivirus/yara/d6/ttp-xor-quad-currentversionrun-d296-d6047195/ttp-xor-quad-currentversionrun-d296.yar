rule TTP_XOR_QUAD_CurrentVersionRun_d296 {
  strings:
    $key_d296 = { 81 f9 [2] a5 f7 [2] 8e db [2] a0 f9 [2] b4 e2 [2] bb f8 [2] a5 e5 [2] a7 e4 [2] bc e2 [2] a0 e5 [2] bc ca }

  condition:
    any of them
}