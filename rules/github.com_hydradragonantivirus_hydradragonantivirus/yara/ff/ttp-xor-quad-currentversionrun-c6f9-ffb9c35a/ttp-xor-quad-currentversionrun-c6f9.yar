rule TTP_XOR_QUAD_CurrentVersionRun_c6f9 {
  strings:
    $key_c6f9 = { 95 96 [2] b1 98 [2] 9a b4 [2] b4 96 [2] a0 8d [2] af 97 [2] b1 8a [2] b3 8b [2] a8 8d [2] b4 8a [2] a8 a5 }

  condition:
    any of them
}