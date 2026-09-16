rule TTP_XOR_QUAD_CurrentVersionRun_fad6 {
  strings:
    $key_fad6 = { a9 b9 [2] 8d b7 [2] a6 9b [2] 88 b9 [2] 9c a2 [2] 93 b8 [2] 8d a5 [2] 8f a4 [2] 94 a2 [2] 88 a5 [2] 94 8a }

  condition:
    any of them
}