rule TTP_XOR_QUAD_CurrentVersionRun_6db6 {
  strings:
    $key_6db6 = { 3e d9 [2] 1a d7 [2] 31 fb [2] 1f d9 [2] 0b c2 [2] 04 d8 [2] 1a c5 [2] 18 c4 [2] 03 c2 [2] 1f c5 [2] 03 ea }

  condition:
    any of them
}