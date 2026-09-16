rule TTP_XOR_QUAD_CurrentVersionRun_1906 {
  strings:
    $key_1906 = { 4a 69 [2] 6e 67 [2] 45 4b [2] 6b 69 [2] 7f 72 [2] 70 68 [2] 6e 75 [2] 6c 74 [2] 77 72 [2] 6b 75 [2] 77 5a }

  condition:
    any of them
}