rule TTP_XOR_QUAD_CurrentVersionRun_44b6 {
  strings:
    $key_44b6 = { 17 d9 [2] 33 d7 [2] 18 fb [2] 36 d9 [2] 22 c2 [2] 2d d8 [2] 33 c5 [2] 31 c4 [2] 2a c2 [2] 36 c5 [2] 2a ea }

  condition:
    any of them
}