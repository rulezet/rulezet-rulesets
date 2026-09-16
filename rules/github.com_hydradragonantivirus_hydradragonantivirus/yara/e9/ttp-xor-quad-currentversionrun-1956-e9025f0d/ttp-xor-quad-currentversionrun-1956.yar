rule TTP_XOR_QUAD_CurrentVersionRun_1956 {
  strings:
    $key_1956 = { 4a 39 [2] 6e 37 [2] 45 1b [2] 6b 39 [2] 7f 22 [2] 70 38 [2] 6e 25 [2] 6c 24 [2] 77 22 [2] 6b 25 [2] 77 0a }

  condition:
    any of them
}