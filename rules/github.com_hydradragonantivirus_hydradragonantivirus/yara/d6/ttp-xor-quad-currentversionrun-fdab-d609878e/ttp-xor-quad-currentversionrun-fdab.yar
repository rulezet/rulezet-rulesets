rule TTP_XOR_QUAD_CurrentVersionRun_fdab {
  strings:
    $key_fdab = { ae c4 [2] 8a ca [2] a1 e6 [2] 8f c4 [2] 9b df [2] 94 c5 [2] 8a d8 [2] 88 d9 [2] 93 df [2] 8f d8 [2] 93 f7 }

  condition:
    any of them
}