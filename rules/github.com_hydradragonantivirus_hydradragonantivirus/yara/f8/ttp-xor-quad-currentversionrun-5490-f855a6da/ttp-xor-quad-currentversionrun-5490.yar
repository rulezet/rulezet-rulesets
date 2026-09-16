rule TTP_XOR_QUAD_CurrentVersionRun_5490 {
  strings:
    $key_5490 = { 07 ff [2] 23 f1 [2] 08 dd [2] 26 ff [2] 32 e4 [2] 3d fe [2] 23 e3 [2] 21 e2 [2] 3a e4 [2] 26 e3 [2] 3a cc }

  condition:
    any of them
}