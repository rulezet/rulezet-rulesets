rule TTP_XOR_QUAD_CurrentVersionRun_fa00 {
  strings:
    $key_fa00 = { a9 6f [2] 8d 61 [2] a6 4d [2] 88 6f [2] 9c 74 [2] 93 6e [2] 8d 73 [2] 8f 72 [2] 94 74 [2] 88 73 [2] 94 5c }

  condition:
    any of them
}