rule TTP_XOR_QUAD_CurrentVersionRun_fa22 {
  strings:
    $key_fa22 = { a9 4d [2] 8d 43 [2] a6 6f [2] 88 4d [2] 9c 56 [2] 93 4c [2] 8d 51 [2] 8f 50 [2] 94 56 [2] 88 51 [2] 94 7e }

  condition:
    any of them
}