rule TTP_XOR_QUAD_CurrentVersionRun_f778 {
  strings:
    $key_f778 = { a4 17 [2] 80 19 [2] ab 35 [2] 85 17 [2] 91 0c [2] 9e 16 [2] 80 0b [2] 82 0a [2] 99 0c [2] 85 0b [2] 99 24 }

  condition:
    any of them
}