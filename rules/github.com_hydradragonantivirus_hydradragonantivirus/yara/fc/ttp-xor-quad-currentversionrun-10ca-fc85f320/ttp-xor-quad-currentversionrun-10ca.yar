rule TTP_XOR_QUAD_CurrentVersionRun_10ca {
  strings:
    $key_10ca = { 43 a5 [2] 67 ab [2] 4c 87 [2] 62 a5 [2] 76 be [2] 79 a4 [2] 67 b9 [2] 65 b8 [2] 7e be [2] 62 b9 [2] 7e 96 }

  condition:
    any of them
}