rule TTP_XOR_QUAD_CurrentVersionRun_4015 {
  strings:
    $key_4015 = { 13 7a [2] 37 74 [2] 1c 58 [2] 32 7a [2] 26 61 [2] 29 7b [2] 37 66 [2] 35 67 [2] 2e 61 [2] 32 66 [2] 2e 49 }

  condition:
    any of them
}