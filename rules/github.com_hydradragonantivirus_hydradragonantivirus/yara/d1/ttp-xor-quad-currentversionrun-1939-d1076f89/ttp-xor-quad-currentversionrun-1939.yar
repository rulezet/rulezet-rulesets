rule TTP_XOR_QUAD_CurrentVersionRun_1939 {
  strings:
    $key_1939 = { 4a 56 [2] 6e 58 [2] 45 74 [2] 6b 56 [2] 7f 4d [2] 70 57 [2] 6e 4a [2] 6c 4b [2] 77 4d [2] 6b 4a [2] 77 65 }

  condition:
    any of them
}