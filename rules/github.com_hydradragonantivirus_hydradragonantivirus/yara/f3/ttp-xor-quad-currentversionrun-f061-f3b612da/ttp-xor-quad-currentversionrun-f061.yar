rule TTP_XOR_QUAD_CurrentVersionRun_f061 {
  strings:
    $key_f061 = { a3 0e [2] 87 00 [2] ac 2c [2] 82 0e [2] 96 15 [2] 99 0f [2] 87 12 [2] 85 13 [2] 9e 15 [2] 82 12 [2] 9e 3d }

  condition:
    any of them
}