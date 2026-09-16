rule TTP_XOR_QUAD_CurrentVersionRun_05ca {
  strings:
    $key_05ca = { 56 a5 [2] 72 ab [2] 59 87 [2] 77 a5 [2] 63 be [2] 6c a4 [2] 72 b9 [2] 70 b8 [2] 6b be [2] 77 b9 [2] 6b 96 }

  condition:
    any of them
}