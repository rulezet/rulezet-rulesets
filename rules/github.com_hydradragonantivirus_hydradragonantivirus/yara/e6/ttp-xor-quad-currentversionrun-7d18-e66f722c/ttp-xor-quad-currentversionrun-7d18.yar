rule TTP_XOR_QUAD_CurrentVersionRun_7d18 {
  strings:
    $key_7d18 = { 2e 77 [2] 0a 79 [2] 21 55 [2] 0f 77 [2] 1b 6c [2] 14 76 [2] 0a 6b [2] 08 6a [2] 13 6c [2] 0f 6b [2] 13 44 }

  condition:
    any of them
}