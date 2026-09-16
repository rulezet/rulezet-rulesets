rule TTP_XOR_QUAD_CurrentVersionRun_fd12 {
  strings:
    $key_fd12 = { ae 7d [2] 8a 73 [2] a1 5f [2] 8f 7d [2] 9b 66 [2] 94 7c [2] 8a 61 [2] 88 60 [2] 93 66 [2] 8f 61 [2] 93 4e }

  condition:
    any of them
}