rule TTP_XOR_QUAD_CurrentVersionRun_6b90 {
  strings:
    $key_6b90 = { 38 ff [2] 1c f1 [2] 37 dd [2] 19 ff [2] 0d e4 [2] 02 fe [2] 1c e3 [2] 1e e2 [2] 05 e4 [2] 19 e3 [2] 05 cc }

  condition:
    any of them
}