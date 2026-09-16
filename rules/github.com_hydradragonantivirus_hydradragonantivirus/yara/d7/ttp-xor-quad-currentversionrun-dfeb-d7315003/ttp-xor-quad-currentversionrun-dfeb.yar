rule TTP_XOR_QUAD_CurrentVersionRun_dfeb {
  strings:
    $key_dfeb = { 8c 84 [2] a8 8a [2] 83 a6 [2] ad 84 [2] b9 9f [2] b6 85 [2] a8 98 [2] aa 99 [2] b1 9f [2] ad 98 [2] b1 b7 }

  condition:
    any of them
}