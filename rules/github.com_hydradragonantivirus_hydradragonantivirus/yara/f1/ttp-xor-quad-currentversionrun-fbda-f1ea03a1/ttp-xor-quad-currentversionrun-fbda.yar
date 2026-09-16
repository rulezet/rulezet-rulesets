rule TTP_XOR_QUAD_CurrentVersionRun_fbda {
  strings:
    $key_fbda = { a8 b5 [2] 8c bb [2] a7 97 [2] 89 b5 [2] 9d ae [2] 92 b4 [2] 8c a9 [2] 8e a8 [2] 95 ae [2] 89 a9 [2] 95 86 }

  condition:
    any of them
}