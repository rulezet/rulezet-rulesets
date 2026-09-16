rule TTP_XOR_QUAD_CurrentVersionRun_fd2d {
  strings:
    $key_fd2d = { ae 42 [2] 8a 4c [2] a1 60 [2] 8f 42 [2] 9b 59 [2] 94 43 [2] 8a 5e [2] 88 5f [2] 93 59 [2] 8f 5e [2] 93 71 }

  condition:
    any of them
}