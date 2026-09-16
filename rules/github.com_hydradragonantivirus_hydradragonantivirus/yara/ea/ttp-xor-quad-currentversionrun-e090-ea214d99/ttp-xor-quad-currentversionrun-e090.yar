rule TTP_XOR_QUAD_CurrentVersionRun_e090 {
  strings:
    $key_e090 = { b3 ff [2] 97 f1 [2] bc dd [2] 92 ff [2] 86 e4 [2] 89 fe [2] 97 e3 [2] 95 e2 [2] 8e e4 [2] 92 e3 [2] 8e cc }

  condition:
    any of them
}