rule TTP_XOR_QUAD_CurrentVersionRun_fd5d {
  strings:
    $key_fd5d = { ae 32 [2] 8a 3c [2] a1 10 [2] 8f 32 [2] 9b 29 [2] 94 33 [2] 8a 2e [2] 88 2f [2] 93 29 [2] 8f 2e [2] 93 01 }

  condition:
    any of them
}