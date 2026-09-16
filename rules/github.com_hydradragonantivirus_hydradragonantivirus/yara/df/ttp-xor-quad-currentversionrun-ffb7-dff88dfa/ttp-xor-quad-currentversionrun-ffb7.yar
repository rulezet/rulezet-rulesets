rule TTP_XOR_QUAD_CurrentVersionRun_ffb7 {
  strings:
    $key_ffb7 = { ac d8 [2] 88 d6 [2] a3 fa [2] 8d d8 [2] 99 c3 [2] 96 d9 [2] 88 c4 [2] 8a c5 [2] 91 c3 [2] 8d c4 [2] 91 eb }

  condition:
    any of them
}