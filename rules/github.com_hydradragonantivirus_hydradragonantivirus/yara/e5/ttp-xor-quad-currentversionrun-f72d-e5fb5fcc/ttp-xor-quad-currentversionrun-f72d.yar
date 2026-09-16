rule TTP_XOR_QUAD_CurrentVersionRun_f72d {
  strings:
    $key_f72d = { a4 42 [2] 80 4c [2] ab 60 [2] 85 42 [2] 91 59 [2] 9e 43 [2] 80 5e [2] 82 5f [2] 99 59 [2] 85 5e [2] 99 71 }

  condition:
    any of them
}