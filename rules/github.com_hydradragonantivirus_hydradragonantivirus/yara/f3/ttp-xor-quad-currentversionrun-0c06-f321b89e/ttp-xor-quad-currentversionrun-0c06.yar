rule TTP_XOR_QUAD_CurrentVersionRun_0c06 {
  strings:
    $key_0c06 = { 5f 69 [2] 7b 67 [2] 50 4b [2] 7e 69 [2] 6a 72 [2] 65 68 [2] 7b 75 [2] 79 74 [2] 62 72 [2] 7e 75 [2] 62 5a }

  condition:
    any of them
}