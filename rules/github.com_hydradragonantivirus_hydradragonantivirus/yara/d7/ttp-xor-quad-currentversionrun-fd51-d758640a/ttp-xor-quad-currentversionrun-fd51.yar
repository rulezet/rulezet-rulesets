rule TTP_XOR_QUAD_CurrentVersionRun_fd51 {
  strings:
    $key_fd51 = { ae 3e [2] 8a 30 [2] a1 1c [2] 8f 3e [2] 9b 25 [2] 94 3f [2] 8a 22 [2] 88 23 [2] 93 25 [2] 8f 22 [2] 93 0d }

  condition:
    any of them
}