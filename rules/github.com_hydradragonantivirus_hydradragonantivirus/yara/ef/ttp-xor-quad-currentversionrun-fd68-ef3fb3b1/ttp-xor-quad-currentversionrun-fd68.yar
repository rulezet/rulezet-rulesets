rule TTP_XOR_QUAD_CurrentVersionRun_fd68 {
  strings:
    $key_fd68 = { ae 07 [2] 8a 09 [2] a1 25 [2] 8f 07 [2] 9b 1c [2] 94 06 [2] 8a 1b [2] 88 1a [2] 93 1c [2] 8f 1b [2] 93 34 }

  condition:
    any of them
}