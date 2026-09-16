rule TTP_XOR_QUAD_CurrentVersionRun_bef3 {
  strings:
    $key_bef3 = { ed 9c [2] c9 92 [2] e2 be [2] cc 9c [2] d8 87 [2] d7 9d [2] c9 80 [2] cb 81 [2] d0 87 [2] cc 80 [2] d0 af }

  condition:
    any of them
}