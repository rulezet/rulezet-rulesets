rule TTP_XOR_QUAD_CurrentVersionRun_3956 {
  strings:
    $key_3956 = { 6a 39 [2] 4e 37 [2] 65 1b [2] 4b 39 [2] 5f 22 [2] 50 38 [2] 4e 25 [2] 4c 24 [2] 57 22 [2] 4b 25 [2] 57 0a }

  condition:
    any of them
}