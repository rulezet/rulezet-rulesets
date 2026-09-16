rule TTP_XOR_QUAD_CurrentVersionRun_3790 {
  strings:
    $key_3790 = { 64 ff [2] 40 f1 [2] 6b dd [2] 45 ff [2] 51 e4 [2] 5e fe [2] 40 e3 [2] 42 e2 [2] 59 e4 [2] 45 e3 [2] 59 cc }

  condition:
    any of them
}