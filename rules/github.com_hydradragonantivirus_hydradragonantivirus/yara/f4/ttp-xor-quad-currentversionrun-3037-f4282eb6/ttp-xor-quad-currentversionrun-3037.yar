rule TTP_XOR_QUAD_CurrentVersionRun_3037 {
  strings:
    $key_3037 = { 63 58 [2] 47 56 [2] 6c 7a [2] 42 58 [2] 56 43 [2] 59 59 [2] 47 44 [2] 45 45 [2] 5e 43 [2] 42 44 [2] 5e 6b }

  condition:
    any of them
}