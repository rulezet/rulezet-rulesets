rule TTP_XOR_QUAD_CurrentVersionRun_3ada {
  strings:
    $key_3ada = { 69 b5 [2] 4d bb [2] 66 97 [2] 48 b5 [2] 5c ae [2] 53 b4 [2] 4d a9 [2] 4f a8 [2] 54 ae [2] 48 a9 [2] 54 86 }

  condition:
    any of them
}