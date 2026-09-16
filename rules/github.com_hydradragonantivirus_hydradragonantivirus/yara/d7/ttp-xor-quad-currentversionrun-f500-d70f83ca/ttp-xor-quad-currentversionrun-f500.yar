rule TTP_XOR_QUAD_CurrentVersionRun_f500 {
  strings:
    $key_f500 = { a6 6f [2] 82 61 [2] a9 4d [2] 87 6f [2] 93 74 [2] 9c 6e [2] 82 73 [2] 80 72 [2] 9b 74 [2] 87 73 [2] 9b 5c }

  condition:
    any of them
}