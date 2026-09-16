rule TTP_XOR_QUAD_CurrentVersionRun_fdb6 {
  strings:
    $key_fdb6 = { ae d9 [2] 8a d7 [2] a1 fb [2] 8f d9 [2] 9b c2 [2] 94 d8 [2] 8a c5 [2] 88 c4 [2] 93 c2 [2] 8f c5 [2] 93 ea }

  condition:
    any of them
}