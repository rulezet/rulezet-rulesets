rule TTP_XOR_QUAD_CurrentVersionRun_31f9 {
  strings:
    $key_31f9 = { 62 96 [2] 46 98 [2] 6d b4 [2] 43 96 [2] 57 8d [2] 58 97 [2] 46 8a [2] 44 8b [2] 5f 8d [2] 43 8a [2] 5f a5 }

  condition:
    any of them
}