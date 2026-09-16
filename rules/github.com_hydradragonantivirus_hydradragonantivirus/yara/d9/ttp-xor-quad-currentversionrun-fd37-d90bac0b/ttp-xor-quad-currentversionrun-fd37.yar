rule TTP_XOR_QUAD_CurrentVersionRun_fd37 {
  strings:
    $key_fd37 = { ae 58 [2] 8a 56 [2] a1 7a [2] 8f 58 [2] 9b 43 [2] 94 59 [2] 8a 44 [2] 88 45 [2] 93 43 [2] 8f 44 [2] 93 6b }

  condition:
    any of them
}