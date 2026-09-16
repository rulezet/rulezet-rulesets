rule TTP_XOR_QUAD_CurrentVersionRun_358b {
  strings:
    $key_358b = { 66 e4 [2] 42 ea [2] 69 c6 [2] 47 e4 [2] 53 ff [2] 5c e5 [2] 42 f8 [2] 40 f9 [2] 5b ff [2] 47 f8 [2] 5b d7 }

  condition:
    any of them
}