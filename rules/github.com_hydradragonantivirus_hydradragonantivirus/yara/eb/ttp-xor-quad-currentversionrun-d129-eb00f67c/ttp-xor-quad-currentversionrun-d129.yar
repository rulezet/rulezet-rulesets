rule TTP_XOR_QUAD_CurrentVersionRun_d129 {
  strings:
    $key_d129 = { 82 46 [2] a6 48 [2] 8d 64 [2] a3 46 [2] b7 5d [2] b8 47 [2] a6 5a [2] a4 5b [2] bf 5d [2] a3 5a [2] bf 75 }

  condition:
    any of them
}