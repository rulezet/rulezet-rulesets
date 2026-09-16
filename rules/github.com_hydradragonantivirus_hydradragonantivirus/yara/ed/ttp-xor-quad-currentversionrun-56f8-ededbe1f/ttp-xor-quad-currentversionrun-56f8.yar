rule TTP_XOR_QUAD_CurrentVersionRun_56f8 {
  strings:
    $key_56f8 = { 05 97 [2] 21 99 [2] 0a b5 [2] 24 97 [2] 30 8c [2] 3f 96 [2] 21 8b [2] 23 8a [2] 38 8c [2] 24 8b [2] 38 a4 }

  condition:
    any of them
}