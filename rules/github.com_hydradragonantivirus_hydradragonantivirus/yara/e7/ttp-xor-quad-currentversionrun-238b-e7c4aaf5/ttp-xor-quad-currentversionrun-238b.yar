rule TTP_XOR_QUAD_CurrentVersionRun_238b {
  strings:
    $key_238b = { 70 e4 [2] 54 ea [2] 7f c6 [2] 51 e4 [2] 45 ff [2] 4a e5 [2] 54 f8 [2] 56 f9 [2] 4d ff [2] 51 f8 [2] 4d d7 }

  condition:
    any of them
}