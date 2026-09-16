rule TTP_XOR_QUAD_CurrentVersionRun_c407 {
  strings:
    $key_c407 = { 97 68 [2] b3 66 [2] 98 4a [2] b6 68 [2] a2 73 [2] ad 69 [2] b3 74 [2] b1 75 [2] aa 73 [2] b6 74 [2] aa 5b }

  condition:
    any of them
}