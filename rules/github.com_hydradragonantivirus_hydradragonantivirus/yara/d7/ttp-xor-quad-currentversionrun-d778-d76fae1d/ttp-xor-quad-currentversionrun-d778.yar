rule TTP_XOR_QUAD_CurrentVersionRun_d778 {
  strings:
    $key_d778 = { 84 17 [2] a0 19 [2] 8b 35 [2] a5 17 [2] b1 0c [2] be 16 [2] a0 0b [2] a2 0a [2] b9 0c [2] a5 0b [2] b9 24 }

  condition:
    any of them
}