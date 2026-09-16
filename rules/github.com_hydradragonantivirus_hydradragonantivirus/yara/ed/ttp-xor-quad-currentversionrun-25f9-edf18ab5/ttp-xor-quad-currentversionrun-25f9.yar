rule TTP_XOR_QUAD_CurrentVersionRun_25f9 {
  strings:
    $key_25f9 = { 76 96 [2] 52 98 [2] 79 b4 [2] 57 96 [2] 43 8d [2] 4c 97 [2] 52 8a [2] 50 8b [2] 4b 8d [2] 57 8a [2] 4b a5 }

  condition:
    any of them
}