rule TTP_XOR_QUAD_CurrentVersionRun_d105 {
  strings:
    $key_d105 = { 82 6a [2] a6 64 [2] 8d 48 [2] a3 6a [2] b7 71 [2] b8 6b [2] a6 76 [2] a4 77 [2] bf 71 [2] a3 76 [2] bf 59 }

  condition:
    any of them
}