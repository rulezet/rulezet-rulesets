rule TTP_XOR_QUAD_CurrentVersionRun_c609 {
  strings:
    $key_c609 = { 95 66 [2] b1 68 [2] 9a 44 [2] b4 66 [2] a0 7d [2] af 67 [2] b1 7a [2] b3 7b [2] a8 7d [2] b4 7a [2] a8 55 }

  condition:
    any of them
}