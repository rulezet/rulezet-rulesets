rule TTP_XOR_QUAD_CurrentVersionRun_3bda {
  strings:
    $key_3bda = { 68 b5 [2] 4c bb [2] 67 97 [2] 49 b5 [2] 5d ae [2] 52 b4 [2] 4c a9 [2] 4e a8 [2] 55 ae [2] 49 a9 [2] 55 86 }

  condition:
    any of them
}