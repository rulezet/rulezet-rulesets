rule TTP_XOR_QUAD_CurrentVersionRun_f755 {
  strings:
    $key_f755 = { a4 3a [2] 80 34 [2] ab 18 [2] 85 3a [2] 91 21 [2] 9e 3b [2] 80 26 [2] 82 27 [2] 99 21 [2] 85 26 [2] 99 09 }

  condition:
    any of them
}