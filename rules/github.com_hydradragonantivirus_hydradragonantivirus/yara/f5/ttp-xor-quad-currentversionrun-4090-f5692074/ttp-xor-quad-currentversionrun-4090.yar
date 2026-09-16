rule TTP_XOR_QUAD_CurrentVersionRun_4090 {
  strings:
    $key_4090 = { 13 ff [2] 37 f1 [2] 1c dd [2] 32 ff [2] 26 e4 [2] 29 fe [2] 37 e3 [2] 35 e2 [2] 2e e4 [2] 32 e3 [2] 2e cc }

  condition:
    any of them
}