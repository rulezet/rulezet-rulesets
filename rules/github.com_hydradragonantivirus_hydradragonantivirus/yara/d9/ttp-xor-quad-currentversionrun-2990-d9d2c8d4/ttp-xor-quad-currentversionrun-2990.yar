rule TTP_XOR_QUAD_CurrentVersionRun_2990 {
  strings:
    $key_2990 = { 7a ff [2] 5e f1 [2] 75 dd [2] 5b ff [2] 4f e4 [2] 40 fe [2] 5e e3 [2] 5c e2 [2] 47 e4 [2] 5b e3 [2] 47 cc }

  condition:
    any of them
}