rule TTP_XOR_QUAD_CurrentVersionRun_f576 {
  strings:
    $key_f576 = { a6 19 [2] 82 17 [2] a9 3b [2] 87 19 [2] 93 02 [2] 9c 18 [2] 82 05 [2] 80 04 [2] 9b 02 [2] 87 05 [2] 9b 2a }

  condition:
    any of them
}