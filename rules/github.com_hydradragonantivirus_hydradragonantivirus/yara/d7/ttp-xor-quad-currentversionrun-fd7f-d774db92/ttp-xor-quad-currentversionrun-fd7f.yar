rule TTP_XOR_QUAD_CurrentVersionRun_fd7f {
  strings:
    $key_fd7f = { ae 10 [2] 8a 1e [2] a1 32 [2] 8f 10 [2] 9b 0b [2] 94 11 [2] 8a 0c [2] 88 0d [2] 93 0b [2] 8f 0c [2] 93 23 }

  condition:
    any of them
}