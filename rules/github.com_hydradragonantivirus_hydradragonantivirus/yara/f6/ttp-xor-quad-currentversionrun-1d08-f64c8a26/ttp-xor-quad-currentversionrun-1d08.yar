rule TTP_XOR_QUAD_CurrentVersionRun_1d08 {
  strings:
    $key_1d08 = { 4e 67 [2] 6a 69 [2] 41 45 [2] 6f 67 [2] 7b 7c [2] 74 66 [2] 6a 7b [2] 68 7a [2] 73 7c [2] 6f 7b [2] 73 54 }

  condition:
    any of them
}