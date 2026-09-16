rule TTP_XOR_QUAD_CurrentVersionRun_d0c6 {
  strings:
    $key_d0c6 = { 83 a9 [2] a7 a7 [2] 8c 8b [2] a2 a9 [2] b6 b2 [2] b9 a8 [2] a7 b5 [2] a5 b4 [2] be b2 [2] a2 b5 [2] be 9a }

  condition:
    any of them
}