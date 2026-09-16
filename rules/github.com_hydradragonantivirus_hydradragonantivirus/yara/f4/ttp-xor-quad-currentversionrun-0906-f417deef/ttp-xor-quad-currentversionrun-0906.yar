rule TTP_XOR_QUAD_CurrentVersionRun_0906 {
  strings:
    $key_0906 = { 5a 69 [2] 7e 67 [2] 55 4b [2] 7b 69 [2] 6f 72 [2] 60 68 [2] 7e 75 [2] 7c 74 [2] 67 72 [2] 7b 75 [2] 67 5a }

  condition:
    any of them
}