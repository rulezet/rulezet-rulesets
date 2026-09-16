rule TTP_XOR_QUAD_CurrentVersionRun_91ca {
  strings:
    $key_91ca = { c2 a5 [2] e6 ab [2] cd 87 [2] e3 a5 [2] f7 be [2] f8 a4 [2] e6 b9 [2] e4 b8 [2] ff be [2] e3 b9 [2] ff 96 }

  condition:
    any of them
}