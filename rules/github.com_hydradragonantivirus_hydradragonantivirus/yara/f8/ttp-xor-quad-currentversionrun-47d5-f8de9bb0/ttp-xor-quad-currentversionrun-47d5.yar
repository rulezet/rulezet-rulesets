rule TTP_XOR_QUAD_CurrentVersionRun_47d5 {
  strings:
    $key_47d5 = { 14 ba [2] 30 b4 [2] 1b 98 [2] 35 ba [2] 21 a1 [2] 2e bb [2] 30 a6 [2] 32 a7 [2] 29 a1 [2] 35 a6 [2] 29 89 }

  condition:
    any of them
}