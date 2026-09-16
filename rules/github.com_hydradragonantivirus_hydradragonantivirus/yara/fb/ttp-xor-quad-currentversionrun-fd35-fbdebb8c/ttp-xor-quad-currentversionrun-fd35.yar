rule TTP_XOR_QUAD_CurrentVersionRun_fd35 {
  strings:
    $key_fd35 = { ae 5a [2] 8a 54 [2] a1 78 [2] 8f 5a [2] 9b 41 [2] 94 5b [2] 8a 46 [2] 88 47 [2] 93 41 [2] 8f 46 [2] 93 69 }

  condition:
    any of them
}