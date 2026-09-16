rule TTP_XOR_QUAD_CurrentVersionRun_deca {
  strings:
    $key_deca = { 8d a5 [2] a9 ab [2] 82 87 [2] ac a5 [2] b8 be [2] b7 a4 [2] a9 b9 [2] ab b8 [2] b0 be [2] ac b9 [2] b0 96 }

  condition:
    any of them
}