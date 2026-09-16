rule TTP_XOR_QUAD_CurrentVersionRun_208c {
  strings:
    $key_208c = { 73 e3 [2] 57 ed [2] 7c c1 [2] 52 e3 [2] 46 f8 [2] 49 e2 [2] 57 ff [2] 55 fe [2] 4e f8 [2] 52 ff [2] 4e d0 }

  condition:
    any of them
}