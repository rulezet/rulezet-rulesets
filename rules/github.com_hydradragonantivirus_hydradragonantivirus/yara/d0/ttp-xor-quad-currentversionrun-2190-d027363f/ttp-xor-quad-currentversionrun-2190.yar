rule TTP_XOR_QUAD_CurrentVersionRun_2190 {
  strings:
    $key_2190 = { 72 ff [2] 56 f1 [2] 7d dd [2] 53 ff [2] 47 e4 [2] 48 fe [2] 56 e3 [2] 54 e2 [2] 4f e4 [2] 53 e3 [2] 4f cc }

  condition:
    any of them
}