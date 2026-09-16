rule TTP_XOR_QUAD_CurrentVersionRun_f506 {
  strings:
    $key_f506 = { a6 69 [2] 82 67 [2] a9 4b [2] 87 69 [2] 93 72 [2] 9c 68 [2] 82 75 [2] 80 74 [2] 9b 72 [2] 87 75 [2] 9b 5a }

  condition:
    any of them
}