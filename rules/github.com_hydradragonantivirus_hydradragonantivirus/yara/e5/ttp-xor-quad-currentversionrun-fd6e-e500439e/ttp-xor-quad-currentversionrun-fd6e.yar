rule TTP_XOR_QUAD_CurrentVersionRun_fd6e {
  strings:
    $key_fd6e = { ae 01 [2] 8a 0f [2] a1 23 [2] 8f 01 [2] 9b 1a [2] 94 00 [2] 8a 1d [2] 88 1c [2] 93 1a [2] 8f 1d [2] 93 32 }

  condition:
    any of them
}