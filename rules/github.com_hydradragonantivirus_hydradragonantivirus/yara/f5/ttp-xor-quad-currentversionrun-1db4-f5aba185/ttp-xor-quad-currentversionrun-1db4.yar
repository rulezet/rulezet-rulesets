rule TTP_XOR_QUAD_CurrentVersionRun_1db4 {
  strings:
    $key_1db4 = { 4e db [2] 6a d5 [2] 41 f9 [2] 6f db [2] 7b c0 [2] 74 da [2] 6a c7 [2] 68 c6 [2] 73 c0 [2] 6f c7 [2] 73 e8 }

  condition:
    any of them
}