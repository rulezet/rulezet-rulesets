rule TTP_XOR_QUAD_CurrentVersionRun_fd19 {
  strings:
    $key_fd19 = { ae 76 [2] 8a 78 [2] a1 54 [2] 8f 76 [2] 9b 6d [2] 94 77 [2] 8a 6a [2] 88 6b [2] 93 6d [2] 8f 6a [2] 93 45 }

  condition:
    any of them
}