rule TTP_XOR_QUAD_CurrentVersionRun_d758 {
  strings:
    $key_d758 = { 84 37 [2] a0 39 [2] 8b 15 [2] a5 37 [2] b1 2c [2] be 36 [2] a0 2b [2] a2 2a [2] b9 2c [2] a5 2b [2] b9 04 }

  condition:
    any of them
}