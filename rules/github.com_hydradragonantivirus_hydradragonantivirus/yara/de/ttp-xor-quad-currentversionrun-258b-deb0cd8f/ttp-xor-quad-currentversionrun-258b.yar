rule TTP_XOR_QUAD_CurrentVersionRun_258b {
  strings:
    $key_258b = { 76 e4 [2] 52 ea [2] 79 c6 [2] 57 e4 [2] 43 ff [2] 4c e5 [2] 52 f8 [2] 50 f9 [2] 4b ff [2] 57 f8 [2] 4b d7 }

  condition:
    any of them
}