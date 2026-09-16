rule TTP_XOR_QUAD_CurrentVersionRun_6c06 {
  strings:
    $key_6c06 = { 3f 69 [2] 1b 67 [2] 30 4b [2] 1e 69 [2] 0a 72 [2] 05 68 [2] 1b 75 [2] 19 74 [2] 02 72 [2] 1e 75 [2] 02 5a }

  condition:
    any of them
}