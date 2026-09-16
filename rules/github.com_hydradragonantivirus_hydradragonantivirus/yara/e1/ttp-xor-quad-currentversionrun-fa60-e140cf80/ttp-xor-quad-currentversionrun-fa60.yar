rule TTP_XOR_QUAD_CurrentVersionRun_fa60 {
  strings:
    $key_fa60 = { a9 0f [2] 8d 01 [2] a6 2d [2] 88 0f [2] 9c 14 [2] 93 0e [2] 8d 13 [2] 8f 12 [2] 94 14 [2] 88 13 [2] 94 3c }

  condition:
    any of them
}