rule TTP_XOR_QUAD_CurrentVersionRun_4ada {
  strings:
    $key_4ada = { 19 b5 [2] 3d bb [2] 16 97 [2] 38 b5 [2] 2c ae [2] 23 b4 [2] 3d a9 [2] 3f a8 [2] 24 ae [2] 38 a9 [2] 24 86 }

  condition:
    any of them
}