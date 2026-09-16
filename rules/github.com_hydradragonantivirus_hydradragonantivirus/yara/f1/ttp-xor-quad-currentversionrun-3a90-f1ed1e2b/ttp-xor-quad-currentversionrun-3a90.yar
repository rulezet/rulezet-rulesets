rule TTP_XOR_QUAD_CurrentVersionRun_3a90 {
  strings:
    $key_3a90 = { 69 ff [2] 4d f1 [2] 66 dd [2] 48 ff [2] 5c e4 [2] 53 fe [2] 4d e3 [2] 4f e2 [2] 54 e4 [2] 48 e3 [2] 54 cc }

  condition:
    any of them
}