rule TTP_XOR_QUAD_CurrentVersionRun_f762 {
  strings:
    $key_f762 = { a4 0d [2] 80 03 [2] ab 2f [2] 85 0d [2] 91 16 [2] 9e 0c [2] 80 11 [2] 82 10 [2] 99 16 [2] 85 11 [2] 99 3e }

  condition:
    any of them
}