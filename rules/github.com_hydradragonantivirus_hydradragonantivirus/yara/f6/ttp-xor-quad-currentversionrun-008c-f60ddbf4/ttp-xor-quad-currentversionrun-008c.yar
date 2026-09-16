rule TTP_XOR_QUAD_CurrentVersionRun_008c {
  strings:
    $key_008c = { 53 e3 [2] 77 ed [2] 5c c1 [2] 72 e3 [2] 66 f8 [2] 69 e2 [2] 77 ff [2] 75 fe [2] 6e f8 [2] 72 ff [2] 6e d0 }

  condition:
    any of them
}