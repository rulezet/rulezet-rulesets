rule TTP_XOR_QUAD_CurrentVersionRun_f745 {
  strings:
    $key_f745 = { a4 2a [2] 80 24 [2] ab 08 [2] 85 2a [2] 91 31 [2] 9e 2b [2] 80 36 [2] 82 37 [2] 99 31 [2] 85 36 [2] 99 19 }

  condition:
    any of them
}