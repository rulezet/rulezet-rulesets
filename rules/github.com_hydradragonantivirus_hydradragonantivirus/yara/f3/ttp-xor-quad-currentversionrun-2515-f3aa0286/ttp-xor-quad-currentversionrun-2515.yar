rule TTP_XOR_QUAD_CurrentVersionRun_2515 {
  strings:
    $key_2515 = { 76 7a [2] 52 74 [2] 79 58 [2] 57 7a [2] 43 61 [2] 4c 7b [2] 52 66 [2] 50 67 [2] 4b 61 [2] 57 66 [2] 4b 49 }

  condition:
    any of them
}