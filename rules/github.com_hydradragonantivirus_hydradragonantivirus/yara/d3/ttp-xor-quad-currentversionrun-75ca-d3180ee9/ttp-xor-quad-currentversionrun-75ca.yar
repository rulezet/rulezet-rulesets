rule TTP_XOR_QUAD_CurrentVersionRun_75ca {
  strings:
    $key_75ca = { 26 a5 [2] 02 ab [2] 29 87 [2] 07 a5 [2] 13 be [2] 1c a4 [2] 02 b9 [2] 00 b8 [2] 1b be [2] 07 b9 [2] 1b 96 }

  condition:
    any of them
}