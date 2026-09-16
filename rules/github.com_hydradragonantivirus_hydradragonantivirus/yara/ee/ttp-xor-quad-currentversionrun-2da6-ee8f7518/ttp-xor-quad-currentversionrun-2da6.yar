rule TTP_XOR_QUAD_CurrentVersionRun_2da6 {
  strings:
    $key_2da6 = { 7e c9 [2] 5a c7 [2] 71 eb [2] 5f c9 [2] 4b d2 [2] 44 c8 [2] 5a d5 [2] 58 d4 [2] 43 d2 [2] 5f d5 [2] 43 fa }

  condition:
    any of them
}