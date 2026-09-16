rule TTP_XOR_QUAD_CurrentVersionRun_d186 {
  strings:
    $key_d186 = { 82 e9 [2] a6 e7 [2] 8d cb [2] a3 e9 [2] b7 f2 [2] b8 e8 [2] a6 f5 [2] a4 f4 [2] bf f2 [2] a3 f5 [2] bf da }

  condition:
    any of them
}