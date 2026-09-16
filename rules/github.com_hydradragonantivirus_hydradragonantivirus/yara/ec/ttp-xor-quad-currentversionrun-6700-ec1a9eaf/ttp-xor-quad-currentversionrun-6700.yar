rule TTP_XOR_QUAD_CurrentVersionRun_6700 {
  strings:
    $key_6700 = { 34 6f [2] 10 61 [2] 3b 4d [2] 15 6f [2] 01 74 [2] 0e 6e [2] 10 73 [2] 12 72 [2] 09 74 [2] 15 73 [2] 09 5c }

  condition:
    any of them
}