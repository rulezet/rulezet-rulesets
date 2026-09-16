rule TTP_XOR_QUAD_CurrentVersionRun_d081 {
  strings:
    $key_d081 = { 83 ee [2] a7 e0 [2] 8c cc [2] a2 ee [2] b6 f5 [2] b9 ef [2] a7 f2 [2] a5 f3 [2] be f5 [2] a2 f2 [2] be dd }

  condition:
    any of them
}