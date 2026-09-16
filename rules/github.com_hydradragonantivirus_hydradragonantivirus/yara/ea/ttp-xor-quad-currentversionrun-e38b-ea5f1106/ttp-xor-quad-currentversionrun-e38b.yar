rule TTP_XOR_QUAD_CurrentVersionRun_e38b {
  strings:
    $key_e38b = { b0 e4 [2] 94 ea [2] bf c6 [2] 91 e4 [2] 85 ff [2] 8a e5 [2] 94 f8 [2] 96 f9 [2] 8d ff [2] 91 f8 [2] 8d d7 }

  condition:
    any of them
}