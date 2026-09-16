rule TTP_XOR_QUAD_CurrentVersionRun_fdf3 {
  strings:
    $key_fdf3 = { ae 9c [2] 8a 92 [2] a1 be [2] 8f 9c [2] 9b 87 [2] 94 9d [2] 8a 80 [2] 88 81 [2] 93 87 [2] 8f 80 [2] 93 af }

  condition:
    any of them
}