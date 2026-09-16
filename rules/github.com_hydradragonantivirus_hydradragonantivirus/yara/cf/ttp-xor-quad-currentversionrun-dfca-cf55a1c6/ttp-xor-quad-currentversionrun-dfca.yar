rule TTP_XOR_QUAD_CurrentVersionRun_dfca {
  strings:
    $key_dfca = { 8c a5 [2] a8 ab [2] 83 87 [2] ad a5 [2] b9 be [2] b6 a4 [2] a8 b9 [2] aa b8 [2] b1 be [2] ad b9 [2] b1 96 }

  condition:
    any of them
}