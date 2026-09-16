rule TTP_XOR_QUAD_CurrentVersionRun_058b {
  strings:
    $key_058b = { 56 e4 [2] 72 ea [2] 59 c6 [2] 77 e4 [2] 63 ff [2] 6c e5 [2] 72 f8 [2] 70 f9 [2] 6b ff [2] 77 f8 [2] 6b d7 }

  condition:
    any of them
}