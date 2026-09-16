rule TTP_XOR_QUAD_CurrentVersionRun_fd34 {
  strings:
    $key_fd34 = { ae 5b [2] 8a 55 [2] a1 79 [2] 8f 5b [2] 9b 40 [2] 94 5a [2] 8a 47 [2] 88 46 [2] 93 40 [2] 8f 47 [2] 93 68 }

  condition:
    any of them
}