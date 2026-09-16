rule TTP_XOR_QUAD_CurrentVersionRun_58c8 {
  strings:
    $key_58c8 = { 0b a7 [2] 2f a9 [2] 04 85 [2] 2a a7 [2] 3e bc [2] 31 a6 [2] 2f bb [2] 2d ba [2] 36 bc [2] 2a bb [2] 36 94 }

  condition:
    any of them
}