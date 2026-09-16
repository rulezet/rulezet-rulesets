rule TTP_XOR_QUAD_CurrentVersionRun_2dab {
  strings:
    $key_2dab = { 7e c4 [2] 5a ca [2] 71 e6 [2] 5f c4 [2] 4b df [2] 44 c5 [2] 5a d8 [2] 58 d9 [2] 43 df [2] 5f d8 [2] 43 f7 }

  condition:
    any of them
}