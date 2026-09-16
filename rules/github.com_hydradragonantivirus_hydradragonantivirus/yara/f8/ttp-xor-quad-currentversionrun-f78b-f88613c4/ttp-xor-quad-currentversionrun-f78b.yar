rule TTP_XOR_QUAD_CurrentVersionRun_f78b {
  strings:
    $key_f78b = { a4 e4 [2] 80 ea [2] ab c6 [2] 85 e4 [2] 91 ff [2] 9e e5 [2] 80 f8 [2] 82 f9 [2] 99 ff [2] 85 f8 [2] 99 d7 }

  condition:
    any of them
}