rule TTP_XOR_QUAD_CurrentVersionRun_78da {
  strings:
    $key_78da = { 2b b5 [2] 0f bb [2] 24 97 [2] 0a b5 [2] 1e ae [2] 11 b4 [2] 0f a9 [2] 0d a8 [2] 16 ae [2] 0a a9 [2] 16 86 }

  condition:
    any of them
}