rule TTP_XOR_QUAD_CurrentVersionRun_d759 {
  strings:
    $key_d759 = { 84 36 [2] a0 38 [2] 8b 14 [2] a5 36 [2] b1 2d [2] be 37 [2] a0 2a [2] a2 2b [2] b9 2d [2] a5 2a [2] b9 05 }

  condition:
    any of them
}