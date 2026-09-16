rule TTP_XOR_QUAD_CurrentVersionRun_fd00 {
  strings:
    $key_fd00 = { ae 6f [2] 8a 61 [2] a1 4d [2] 8f 6f [2] 9b 74 [2] 94 6e [2] 8a 73 [2] 88 72 [2] 93 74 [2] 8f 73 [2] 93 5c }

  condition:
    any of them
}