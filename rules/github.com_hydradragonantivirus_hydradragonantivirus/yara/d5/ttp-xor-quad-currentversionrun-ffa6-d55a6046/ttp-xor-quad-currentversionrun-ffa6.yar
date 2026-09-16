rule TTP_XOR_QUAD_CurrentVersionRun_ffa6 {
  strings:
    $key_ffa6 = { ac c9 [2] 88 c7 [2] a3 eb [2] 8d c9 [2] 99 d2 [2] 96 c8 [2] 88 d5 [2] 8a d4 [2] 91 d2 [2] 8d d5 [2] 91 fa }

  condition:
    any of them
}