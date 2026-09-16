rule TTP_XOR_QUAD_CurrentVersionRun_fd54 {
  strings:
    $key_fd54 = { ae 3b [2] 8a 35 [2] a1 19 [2] 8f 3b [2] 9b 20 [2] 94 3a [2] 8a 27 [2] 88 26 [2] 93 20 [2] 8f 27 [2] 93 08 }

  condition:
    any of them
}