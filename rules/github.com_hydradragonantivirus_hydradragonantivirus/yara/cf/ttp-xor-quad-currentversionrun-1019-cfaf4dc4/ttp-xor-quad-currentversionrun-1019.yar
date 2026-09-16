rule TTP_XOR_QUAD_CurrentVersionRun_1019 {
  strings:
    $key_1019 = { 43 76 [2] 67 78 [2] 4c 54 [2] 62 76 [2] 76 6d [2] 79 77 [2] 67 6a [2] 65 6b [2] 7e 6d [2] 62 6a [2] 7e 45 }

  condition:
    any of them
}