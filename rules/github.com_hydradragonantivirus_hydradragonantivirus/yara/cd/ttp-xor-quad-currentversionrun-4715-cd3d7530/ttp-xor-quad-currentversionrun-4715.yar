rule TTP_XOR_QUAD_CurrentVersionRun_4715 {
  strings:
    $key_4715 = { 14 7a [2] 30 74 [2] 1b 58 [2] 35 7a [2] 21 61 [2] 2e 7b [2] 30 66 [2] 32 67 [2] 29 61 [2] 35 66 [2] 29 49 }

  condition:
    any of them
}