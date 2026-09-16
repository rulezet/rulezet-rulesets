rule TTP_XOR_QUAD_CurrentVersionRun_f723 {
  strings:
    $key_f723 = { a4 4c [2] 80 42 [2] ab 6e [2] 85 4c [2] 91 57 [2] 9e 4d [2] 80 50 [2] 82 51 [2] 99 57 [2] 85 50 [2] 99 7f }

  condition:
    any of them
}