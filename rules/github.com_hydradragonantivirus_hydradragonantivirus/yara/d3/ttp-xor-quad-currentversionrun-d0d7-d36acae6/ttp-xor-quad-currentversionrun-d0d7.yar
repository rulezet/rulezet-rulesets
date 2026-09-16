rule TTP_XOR_QUAD_CurrentVersionRun_d0d7 {
  strings:
    $key_d0d7 = { 83 b8 [2] a7 b6 [2] 8c 9a [2] a2 b8 [2] b6 a3 [2] b9 b9 [2] a7 a4 [2] a5 a5 [2] be a3 [2] a2 a4 [2] be 8b }

  condition:
    any of them
}