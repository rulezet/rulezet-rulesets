rule TTP_XOR_QUAD_CurrentVersionRun_7524 {
  strings:
    $key_7524 = { 26 4b [2] 02 45 [2] 29 69 [2] 07 4b [2] 13 50 [2] 1c 4a [2] 02 57 [2] 00 56 [2] 1b 50 [2] 07 57 [2] 1b 78 }

  condition:
    any of them
}