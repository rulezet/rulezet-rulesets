rule TTP_XOR_QUAD_CurrentVersionRun_1790 {
  strings:
    $key_1790 = { 44 ff [2] 60 f1 [2] 4b dd [2] 65 ff [2] 71 e4 [2] 7e fe [2] 60 e3 [2] 62 e2 [2] 79 e4 [2] 65 e3 [2] 79 cc }

  condition:
    any of them
}