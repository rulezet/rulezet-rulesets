rule TTP_XOR_QUAD_CurrentVersionRun_2aca {
  strings:
    $key_2aca = { 79 a5 [2] 5d ab [2] 76 87 [2] 58 a5 [2] 4c be [2] 43 a4 [2] 5d b9 [2] 5f b8 [2] 44 be [2] 58 b9 [2] 44 96 }

  condition:
    any of them
}