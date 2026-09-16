rule TTP_XOR_QUAD_CurrentVersionRun_2539 {
  strings:
    $key_2539 = { 76 56 [2] 52 58 [2] 79 74 [2] 57 56 [2] 43 4d [2] 4c 57 [2] 52 4a [2] 50 4b [2] 4b 4d [2] 57 4a [2] 4b 65 }

  condition:
    any of them
}