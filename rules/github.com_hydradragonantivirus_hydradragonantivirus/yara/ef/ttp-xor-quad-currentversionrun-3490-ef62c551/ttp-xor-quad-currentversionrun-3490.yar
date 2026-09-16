rule TTP_XOR_QUAD_CurrentVersionRun_3490 {
  strings:
    $key_3490 = { 67 ff [2] 43 f1 [2] 68 dd [2] 46 ff [2] 52 e4 [2] 5d fe [2] 43 e3 [2] 41 e2 [2] 5a e4 [2] 46 e3 [2] 5a cc }

  condition:
    any of them
}