rule TTP_XOR_QUAD_CurrentVersionRun_fd59 {
  strings:
    $key_fd59 = { ae 36 [2] 8a 38 [2] a1 14 [2] 8f 36 [2] 9b 2d [2] 94 37 [2] 8a 2a [2] 88 2b [2] 93 2d [2] 8f 2a [2] 93 05 }

  condition:
    any of them
}