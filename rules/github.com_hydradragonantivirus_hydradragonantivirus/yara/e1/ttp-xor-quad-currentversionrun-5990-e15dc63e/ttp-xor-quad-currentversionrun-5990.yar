rule TTP_XOR_QUAD_CurrentVersionRun_5990 {
  strings:
    $key_5990 = { 0a ff [2] 2e f1 [2] 05 dd [2] 2b ff [2] 3f e4 [2] 30 fe [2] 2e e3 [2] 2c e2 [2] 37 e4 [2] 2b e3 [2] 37 cc }

  condition:
    any of them
}