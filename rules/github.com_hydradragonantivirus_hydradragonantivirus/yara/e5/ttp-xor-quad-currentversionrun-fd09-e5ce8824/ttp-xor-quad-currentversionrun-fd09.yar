rule TTP_XOR_QUAD_CurrentVersionRun_fd09 {
  strings:
    $key_fd09 = { ae 66 [2] 8a 68 [2] a1 44 [2] 8f 66 [2] 9b 7d [2] 94 67 [2] 8a 7a [2] 88 7b [2] 93 7d [2] 8f 7a [2] 93 55 }

  condition:
    any of them
}