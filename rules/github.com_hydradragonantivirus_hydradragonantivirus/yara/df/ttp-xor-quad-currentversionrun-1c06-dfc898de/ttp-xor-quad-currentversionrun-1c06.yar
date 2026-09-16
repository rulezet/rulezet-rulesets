rule TTP_XOR_QUAD_CurrentVersionRun_1c06 {
  strings:
    $key_1c06 = { 4f 69 [2] 6b 67 [2] 40 4b [2] 6e 69 [2] 7a 72 [2] 75 68 [2] 6b 75 [2] 69 74 [2] 72 72 [2] 6e 75 [2] 72 5a }

  condition:
    any of them
}