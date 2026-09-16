rule TTP_XOR_QUAD_CurrentVersionRun_f774 {
  strings:
    $key_f774 = { a4 1b [2] 80 15 [2] ab 39 [2] 85 1b [2] 91 00 [2] 9e 1a [2] 80 07 [2] 82 06 [2] 99 00 [2] 85 07 [2] 99 28 }

  condition:
    any of them
}