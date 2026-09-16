rule TTP_XOR_QUAD_CurrentVersionRun_d754 {
  strings:
    $key_d754 = { 84 3b [2] a0 35 [2] 8b 19 [2] a5 3b [2] b1 20 [2] be 3a [2] a0 27 [2] a2 26 [2] b9 20 [2] a5 27 [2] b9 08 }

  condition:
    any of them
}