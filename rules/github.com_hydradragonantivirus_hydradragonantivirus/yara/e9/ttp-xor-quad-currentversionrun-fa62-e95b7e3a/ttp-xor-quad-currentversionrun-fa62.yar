rule TTP_XOR_QUAD_CurrentVersionRun_fa62 {
  strings:
    $key_fa62 = { a9 0d [2] 8d 03 [2] a6 2f [2] 88 0d [2] 9c 16 [2] 93 0c [2] 8d 11 [2] 8f 10 [2] 94 16 [2] 88 11 [2] 94 3e }

  condition:
    any of them
}