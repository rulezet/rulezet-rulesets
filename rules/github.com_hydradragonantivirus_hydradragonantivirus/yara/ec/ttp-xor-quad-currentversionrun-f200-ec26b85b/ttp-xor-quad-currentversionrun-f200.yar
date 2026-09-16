rule TTP_XOR_QUAD_CurrentVersionRun_f200 {
  strings:
    $key_f200 = { a1 6f [2] 85 61 [2] ae 4d [2] 80 6f [2] 94 74 [2] 9b 6e [2] 85 73 [2] 87 72 [2] 9c 74 [2] 80 73 [2] 9c 5c }

  condition:
    any of them
}