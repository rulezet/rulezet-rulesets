rule TTP_XOR_QUAD_CurrentVersionRun_fda6 {
  strings:
    $key_fda6 = { ae c9 [2] 8a c7 [2] a1 eb [2] 8f c9 [2] 9b d2 [2] 94 c8 [2] 8a d5 [2] 88 d4 [2] 93 d2 [2] 8f d5 [2] 93 fa }

  condition:
    any of them
}