rule TTP_XOR_QUAD_CurrentVersionRun_fd13 {
  strings:
    $key_fd13 = { ae 7c [2] 8a 72 [2] a1 5e [2] 8f 7c [2] 9b 67 [2] 94 7d [2] 8a 60 [2] 88 61 [2] 93 67 [2] 8f 60 [2] 93 4f }

  condition:
    any of them
}