rule TTP_XOR_QUAD_CurrentVersionRun_758b {
  strings:
    $key_758b = { 26 e4 [2] 02 ea [2] 29 c6 [2] 07 e4 [2] 13 ff [2] 1c e5 [2] 02 f8 [2] 00 f9 [2] 1b ff [2] 07 f8 [2] 1b d7 }

  condition:
    any of them
}