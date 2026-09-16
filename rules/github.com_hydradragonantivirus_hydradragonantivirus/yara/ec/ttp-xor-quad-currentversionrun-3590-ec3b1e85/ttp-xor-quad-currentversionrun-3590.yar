rule TTP_XOR_QUAD_CurrentVersionRun_3590 {
  strings:
    $key_3590 = { 66 ff [2] 42 f1 [2] 69 dd [2] 47 ff [2] 53 e4 [2] 5c fe [2] 42 e3 [2] 40 e2 [2] 5b e4 [2] 47 e3 [2] 5b cc }

  condition:
    any of them
}