rule TTP_XOR_QUAD_CurrentVersionRun_fd30 {
  strings:
    $key_fd30 = { ae 5f [2] 8a 51 [2] a1 7d [2] 8f 5f [2] 9b 44 [2] 94 5e [2] 8a 43 [2] 88 42 [2] 93 44 [2] 8f 43 [2] 93 6c }

  condition:
    any of them
}