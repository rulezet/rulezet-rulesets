rule TTP_XOR_QUAD_CurrentVersionRun_fdf7 {
  strings:
    $key_fdf7 = { ae 98 [2] 8a 96 [2] a1 ba [2] 8f 98 [2] 9b 83 [2] 94 99 [2] 8a 84 [2] 88 85 [2] 93 83 [2] 8f 84 [2] 93 ab }

  condition:
    any of them
}