rule TTP_XOR_QUAD_CurrentVersionRun_4718 {
  strings:
    $key_4718 = { 14 77 [2] 30 79 [2] 1b 55 [2] 35 77 [2] 21 6c [2] 2e 76 [2] 30 6b [2] 32 6a [2] 29 6c [2] 35 6b [2] 29 44 }

  condition:
    any of them
}