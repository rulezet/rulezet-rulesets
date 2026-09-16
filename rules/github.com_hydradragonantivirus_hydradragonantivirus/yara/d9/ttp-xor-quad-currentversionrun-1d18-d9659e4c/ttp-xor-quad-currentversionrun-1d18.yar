rule TTP_XOR_QUAD_CurrentVersionRun_1d18 {
  strings:
    $key_1d18 = { 4e 77 [2] 6a 79 [2] 41 55 [2] 6f 77 [2] 7b 6c [2] 74 76 [2] 6a 6b [2] 68 6a [2] 73 6c [2] 6f 6b [2] 73 44 }

  condition:
    any of them
}