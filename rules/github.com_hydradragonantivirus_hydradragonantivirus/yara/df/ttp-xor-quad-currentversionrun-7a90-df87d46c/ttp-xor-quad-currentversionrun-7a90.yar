rule TTP_XOR_QUAD_CurrentVersionRun_7a90 {
  strings:
    $key_7a90 = { 29 ff [2] 0d f1 [2] 26 dd [2] 08 ff [2] 1c e4 [2] 13 fe [2] 0d e3 [2] 0f e2 [2] 14 e4 [2] 08 e3 [2] 14 cc }

  condition:
    any of them
}