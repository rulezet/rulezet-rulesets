rule TTP_XOR_QUAD_CurrentVersionRun_eaa6 {
  strings:
    $key_eaa6 = { b9 c9 [2] 9d c7 [2] b6 eb [2] 98 c9 [2] 8c d2 [2] 83 c8 [2] 9d d5 [2] 9f d4 [2] 84 d2 [2] 98 d5 [2] 84 fa }

  condition:
    any of them
}