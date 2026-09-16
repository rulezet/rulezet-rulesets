rule TTP_XOR_QUAD_CurrentVersionRun_5cc8 {
  strings:
    $key_5cc8 = { 0f a7 [2] 2b a9 [2] 00 85 [2] 2e a7 [2] 3a bc [2] 35 a6 [2] 2b bb [2] 29 ba [2] 32 bc [2] 2e bb [2] 32 94 }

  condition:
    any of them
}