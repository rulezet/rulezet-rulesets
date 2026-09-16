rule TTP_XOR_QUAD_CurrentVersionRun_1cd4 {
  strings:
    $key_1cd4 = { 4f bb [2] 6b b5 [2] 40 99 [2] 6e bb [2] 7a a0 [2] 75 ba [2] 6b a7 [2] 69 a6 [2] 72 a0 [2] 6e a7 [2] 72 88 }

  condition:
    any of them
}