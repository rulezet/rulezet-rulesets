rule TTP_XOR_QUAD_CurrentVersionRun_f76c {
  strings:
    $key_f76c = { a4 03 [2] 80 0d [2] ab 21 [2] 85 03 [2] 91 18 [2] 9e 02 [2] 80 1f [2] 82 1e [2] 99 18 [2] 85 1f [2] 99 30 }

  condition:
    any of them
}