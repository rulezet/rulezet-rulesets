rule TTP_XOR_QUAD_CurrentVersionRun_32ca {
  strings:
    $key_32ca = { 61 a5 [2] 45 ab [2] 6e 87 [2] 40 a5 [2] 54 be [2] 5b a4 [2] 45 b9 [2] 47 b8 [2] 5c be [2] 40 b9 [2] 5c 96 }

  condition:
    any of them
}