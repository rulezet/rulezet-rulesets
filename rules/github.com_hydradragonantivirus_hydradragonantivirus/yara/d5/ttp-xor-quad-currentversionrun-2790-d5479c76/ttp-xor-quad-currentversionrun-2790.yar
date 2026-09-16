rule TTP_XOR_QUAD_CurrentVersionRun_2790 {
  strings:
    $key_2790 = { 74 ff [2] 50 f1 [2] 7b dd [2] 55 ff [2] 41 e4 [2] 4e fe [2] 50 e3 [2] 52 e2 [2] 49 e4 [2] 55 e3 [2] 49 cc }

  condition:
    any of them
}