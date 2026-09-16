rule TTP_XOR_QUAD_CurrentVersionRun_6db4 {
  strings:
    $key_6db4 = { 3e db [2] 1a d5 [2] 31 f9 [2] 1f db [2] 0b c0 [2] 04 da [2] 1a c7 [2] 18 c6 [2] 03 c0 [2] 1f c7 [2] 03 e8 }

  condition:
    any of them
}