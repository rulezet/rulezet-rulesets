rule TTP_XOR_QUAD_CurrentVersionRun_6dda {
  strings:
    $key_6dda = { 3e b5 [2] 1a bb [2] 31 97 [2] 1f b5 [2] 0b ae [2] 04 b4 [2] 1a a9 [2] 18 a8 [2] 03 ae [2] 1f a9 [2] 03 86 }

  condition:
    any of them
}