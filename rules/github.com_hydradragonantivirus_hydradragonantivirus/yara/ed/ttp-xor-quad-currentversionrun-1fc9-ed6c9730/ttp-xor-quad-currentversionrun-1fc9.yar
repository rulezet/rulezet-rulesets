rule TTP_XOR_QUAD_CurrentVersionRun_1fc9 {
  strings:
    $key_1fc9 = { 4c a6 [2] 68 a8 [2] 43 84 [2] 6d a6 [2] 79 bd [2] 76 a7 [2] 68 ba [2] 6a bb [2] 71 bd [2] 6d ba [2] 71 95 }

  condition:
    any of them
}