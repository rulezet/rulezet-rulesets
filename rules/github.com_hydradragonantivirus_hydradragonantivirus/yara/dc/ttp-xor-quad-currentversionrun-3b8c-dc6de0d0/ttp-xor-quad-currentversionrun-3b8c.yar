rule TTP_XOR_QUAD_CurrentVersionRun_3b8c {
  strings:
    $key_3b8c = { 68 e3 [2] 4c ed [2] 67 c1 [2] 49 e3 [2] 5d f8 [2] 52 e2 [2] 4c ff [2] 4e fe [2] 55 f8 [2] 49 ff [2] 55 d0 }

  condition:
    any of them
}