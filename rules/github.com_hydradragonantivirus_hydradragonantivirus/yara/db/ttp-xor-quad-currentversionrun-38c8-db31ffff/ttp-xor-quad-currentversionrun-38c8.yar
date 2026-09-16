rule TTP_XOR_QUAD_CurrentVersionRun_38c8 {
  strings:
    $key_38c8 = { 6b a7 [2] 4f a9 [2] 64 85 [2] 4a a7 [2] 5e bc [2] 51 a6 [2] 4f bb [2] 4d ba [2] 56 bc [2] 4a bb [2] 56 94 }

  condition:
    any of them
}