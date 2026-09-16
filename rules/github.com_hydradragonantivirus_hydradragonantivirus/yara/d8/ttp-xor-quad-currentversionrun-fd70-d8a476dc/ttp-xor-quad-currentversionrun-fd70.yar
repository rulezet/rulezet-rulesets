rule TTP_XOR_QUAD_CurrentVersionRun_fd70 {
  strings:
    $key_fd70 = { ae 1f [2] 8a 11 [2] a1 3d [2] 8f 1f [2] 9b 04 [2] 94 1e [2] 8a 03 [2] 88 02 [2] 93 04 [2] 8f 03 [2] 93 2c }

  condition:
    any of them
}