rule TTP_XOR_QUAD_CurrentVersionRun_2d08 {
  strings:
    $key_2d08 = { 7e 67 [2] 5a 69 [2] 71 45 [2] 5f 67 [2] 4b 7c [2] 44 66 [2] 5a 7b [2] 58 7a [2] 43 7c [2] 5f 7b [2] 43 54 }

  condition:
    any of them
}