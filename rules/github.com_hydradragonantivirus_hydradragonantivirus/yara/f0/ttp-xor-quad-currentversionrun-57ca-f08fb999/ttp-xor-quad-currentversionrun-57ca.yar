rule TTP_XOR_QUAD_CurrentVersionRun_57ca {
  strings:
    $key_57ca = { 04 a5 [2] 20 ab [2] 0b 87 [2] 25 a5 [2] 31 be [2] 3e a4 [2] 20 b9 [2] 22 b8 [2] 39 be [2] 25 b9 [2] 39 96 }

  condition:
    any of them
}