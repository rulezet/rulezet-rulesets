rule TTP_XOR_QUAD_CurrentVersionRun_fd4f {
  strings:
    $key_fd4f = { ae 20 [2] 8a 2e [2] a1 02 [2] 8f 20 [2] 9b 3b [2] 94 21 [2] 8a 3c [2] 88 3d [2] 93 3b [2] 8f 3c [2] 93 13 }

  condition:
    any of them
}