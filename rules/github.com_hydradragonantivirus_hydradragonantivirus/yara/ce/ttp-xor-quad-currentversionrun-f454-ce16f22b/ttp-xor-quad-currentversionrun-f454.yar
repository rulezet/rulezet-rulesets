rule TTP_XOR_QUAD_CurrentVersionRun_f454 {
  strings:
    $key_f454 = { a7 3b [2] 83 35 [2] a8 19 [2] 86 3b [2] 92 20 [2] 9d 3a [2] 83 27 [2] 81 26 [2] 9a 20 [2] 86 27 [2] 9a 08 }

  condition:
    any of them
}