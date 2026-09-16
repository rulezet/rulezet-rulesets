rule TTP_XOR_QUAD_CurrentVersionRun_1390 {
  strings:
    $key_1390 = { 40 ff [2] 64 f1 [2] 4f dd [2] 61 ff [2] 75 e4 [2] 7a fe [2] 64 e3 [2] 66 e2 [2] 7d e4 [2] 61 e3 [2] 7d cc }

  condition:
    any of them
}