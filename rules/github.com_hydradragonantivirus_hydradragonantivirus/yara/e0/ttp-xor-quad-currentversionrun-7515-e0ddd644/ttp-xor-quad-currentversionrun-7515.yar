rule TTP_XOR_QUAD_CurrentVersionRun_7515 {
  strings:
    $key_7515 = { 26 7a [2] 02 74 [2] 29 58 [2] 07 7a [2] 13 61 [2] 1c 7b [2] 02 66 [2] 00 67 [2] 1b 61 [2] 07 66 [2] 1b 49 }

  condition:
    any of them
}