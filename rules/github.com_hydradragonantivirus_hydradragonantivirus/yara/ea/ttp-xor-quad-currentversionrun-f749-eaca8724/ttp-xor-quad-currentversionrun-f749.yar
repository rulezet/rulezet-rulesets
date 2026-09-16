rule TTP_XOR_QUAD_CurrentVersionRun_f749 {
  strings:
    $key_f749 = { a4 26 [2] 80 28 [2] ab 04 [2] 85 26 [2] 91 3d [2] 9e 27 [2] 80 3a [2] 82 3b [2] 99 3d [2] 85 3a [2] 99 15 }

  condition:
    any of them
}