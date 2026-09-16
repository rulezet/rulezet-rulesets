rule TTP_XOR_QUAD_CurrentVersionRun_c606 {
  strings:
    $key_c606 = { 95 69 [2] b1 67 [2] 9a 4b [2] b4 69 [2] a0 72 [2] af 68 [2] b1 75 [2] b3 74 [2] a8 72 [2] b4 75 [2] a8 5a }

  condition:
    any of them
}