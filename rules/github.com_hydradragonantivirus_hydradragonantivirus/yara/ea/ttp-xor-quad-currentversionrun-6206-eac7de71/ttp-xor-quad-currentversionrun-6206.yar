rule TTP_XOR_QUAD_CurrentVersionRun_6206 {
  strings:
    $key_6206 = { 31 69 [2] 15 67 [2] 3e 4b [2] 10 69 [2] 04 72 [2] 0b 68 [2] 15 75 [2] 17 74 [2] 0c 72 [2] 10 75 [2] 0c 5a }

  condition:
    any of them
}