rule TTP_XOR_QUAD_CurrentVersionRun_f756 {
  strings:
    $key_f756 = { a4 39 [2] 80 37 [2] ab 1b [2] 85 39 [2] 91 22 [2] 9e 38 [2] 80 25 [2] 82 24 [2] 99 22 [2] 85 25 [2] 99 0a }

  condition:
    any of them
}