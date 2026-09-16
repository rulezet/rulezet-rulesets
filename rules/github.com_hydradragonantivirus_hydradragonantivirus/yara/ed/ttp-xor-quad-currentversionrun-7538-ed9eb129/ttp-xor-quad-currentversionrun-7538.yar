rule TTP_XOR_QUAD_CurrentVersionRun_7538 {
  strings:
    $key_7538 = { 26 57 [2] 02 59 [2] 29 75 [2] 07 57 [2] 13 4c [2] 1c 56 [2] 02 4b [2] 00 4a [2] 1b 4c [2] 07 4b [2] 1b 64 }

  condition:
    any of them
}