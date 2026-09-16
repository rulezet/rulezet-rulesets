rule TTP_XOR_QUAD_CurrentVersionRun_fd69 {
  strings:
    $key_fd69 = { ae 06 [2] 8a 08 [2] a1 24 [2] 8f 06 [2] 9b 1d [2] 94 07 [2] 8a 1a [2] 88 1b [2] 93 1d [2] 8f 1a [2] 93 35 }

  condition:
    any of them
}