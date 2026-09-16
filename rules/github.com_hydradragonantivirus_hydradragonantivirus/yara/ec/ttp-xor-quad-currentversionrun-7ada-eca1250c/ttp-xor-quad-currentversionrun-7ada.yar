rule TTP_XOR_QUAD_CurrentVersionRun_7ada {
  strings:
    $key_7ada = { 29 b5 [2] 0d bb [2] 26 97 [2] 08 b5 [2] 1c ae [2] 13 b4 [2] 0d a9 [2] 0f a8 [2] 14 ae [2] 08 a9 [2] 14 86 }

  condition:
    any of them
}