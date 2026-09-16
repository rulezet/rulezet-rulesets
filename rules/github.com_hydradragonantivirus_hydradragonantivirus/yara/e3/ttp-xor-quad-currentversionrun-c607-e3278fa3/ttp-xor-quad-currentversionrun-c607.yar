rule TTP_XOR_QUAD_CurrentVersionRun_c607 {
  strings:
    $key_c607 = { 95 68 [2] b1 66 [2] 9a 4a [2] b4 68 [2] a0 73 [2] af 69 [2] b1 74 [2] b3 75 [2] a8 73 [2] b4 74 [2] a8 5b }

  condition:
    any of them
}