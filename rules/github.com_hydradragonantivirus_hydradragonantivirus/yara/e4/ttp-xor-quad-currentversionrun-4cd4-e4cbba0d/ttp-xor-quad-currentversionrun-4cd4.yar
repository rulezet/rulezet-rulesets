rule TTP_XOR_QUAD_CurrentVersionRun_4cd4 {
  strings:
    $key_4cd4 = { 1f bb [2] 3b b5 [2] 10 99 [2] 3e bb [2] 2a a0 [2] 25 ba [2] 3b a7 [2] 39 a6 [2] 22 a0 [2] 3e a7 [2] 22 88 }

  condition:
    any of them
}