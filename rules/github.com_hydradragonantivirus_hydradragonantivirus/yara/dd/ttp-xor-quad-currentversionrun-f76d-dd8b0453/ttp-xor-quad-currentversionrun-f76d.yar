rule TTP_XOR_QUAD_CurrentVersionRun_f76d {
  strings:
    $key_f76d = { a4 02 [2] 80 0c [2] ab 20 [2] 85 02 [2] 91 19 [2] 9e 03 [2] 80 1e [2] 82 1f [2] 99 19 [2] 85 1e [2] 99 31 }

  condition:
    any of them
}