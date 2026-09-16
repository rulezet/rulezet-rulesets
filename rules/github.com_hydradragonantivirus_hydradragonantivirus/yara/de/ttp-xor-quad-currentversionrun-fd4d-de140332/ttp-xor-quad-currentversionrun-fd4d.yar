rule TTP_XOR_QUAD_CurrentVersionRun_fd4d {
  strings:
    $key_fd4d = { ae 22 [2] 8a 2c [2] a1 00 [2] 8f 22 [2] 9b 39 [2] 94 23 [2] 8a 3e [2] 88 3f [2] 93 39 [2] 8f 3e [2] 93 11 }

  condition:
    any of them
}