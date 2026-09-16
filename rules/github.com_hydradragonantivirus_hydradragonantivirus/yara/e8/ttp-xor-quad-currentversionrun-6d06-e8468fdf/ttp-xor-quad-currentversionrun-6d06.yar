rule TTP_XOR_QUAD_CurrentVersionRun_6d06 {
  strings:
    $key_6d06 = { 3e 69 [2] 1a 67 [2] 31 4b [2] 1f 69 [2] 0b 72 [2] 04 68 [2] 1a 75 [2] 18 74 [2] 03 72 [2] 1f 75 [2] 03 5a }

  condition:
    any of them
}