rule TTP_XOR_QUAD_CurrentVersionRun_7bda {
  strings:
    $key_7bda = { 28 b5 [2] 0c bb [2] 27 97 [2] 09 b5 [2] 1d ae [2] 12 b4 [2] 0c a9 [2] 0e a8 [2] 15 ae [2] 09 a9 [2] 15 86 }

  condition:
    any of them
}