rule TTP_XOR_QUAD_CurrentVersionRun_d639 {
  strings:
    $key_d639 = { 85 56 [2] a1 58 [2] 8a 74 [2] a4 56 [2] b0 4d [2] bf 57 [2] a1 4a [2] a3 4b [2] b8 4d [2] a4 4a [2] b8 65 }

  condition:
    any of them
}