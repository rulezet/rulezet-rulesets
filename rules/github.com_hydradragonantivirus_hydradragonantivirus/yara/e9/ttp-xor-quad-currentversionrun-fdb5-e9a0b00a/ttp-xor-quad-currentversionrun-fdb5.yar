rule TTP_XOR_QUAD_CurrentVersionRun_fdb5 {
  strings:
    $key_fdb5 = { ae da [2] 8a d4 [2] a1 f8 [2] 8f da [2] 9b c1 [2] 94 db [2] 8a c6 [2] 88 c7 [2] 93 c1 [2] 8f c6 [2] 93 e9 }

  condition:
    any of them
}