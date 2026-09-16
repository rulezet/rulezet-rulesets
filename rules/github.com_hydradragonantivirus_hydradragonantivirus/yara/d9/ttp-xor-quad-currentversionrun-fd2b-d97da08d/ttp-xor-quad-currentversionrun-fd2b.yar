rule TTP_XOR_QUAD_CurrentVersionRun_fd2b {
  strings:
    $key_fd2b = { ae 44 [2] 8a 4a [2] a1 66 [2] 8f 44 [2] 9b 5f [2] 94 45 [2] 8a 58 [2] 88 59 [2] 93 5f [2] 8f 58 [2] 93 77 }

  condition:
    any of them
}