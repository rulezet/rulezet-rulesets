rule TTP_XOR_QUAD_CurrentVersionRun_f700 {
  strings:
    $key_f700 = { a4 6f [2] 80 61 [2] ab 4d [2] 85 6f [2] 91 74 [2] 9e 6e [2] 80 73 [2] 82 72 [2] 99 74 [2] 85 73 [2] 99 5c }

  condition:
    any of them
}