rule TTP_XOR_QUAD_CurrentVersionRun_28f8 {
  strings:
    $key_28f8 = { 7b 97 [2] 5f 99 [2] 74 b5 [2] 5a 97 [2] 4e 8c [2] 41 96 [2] 5f 8b [2] 5d 8a [2] 46 8c [2] 5a 8b [2] 46 a4 }

  condition:
    any of them
}