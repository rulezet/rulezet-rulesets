rule TTP_XOR_QUAD_CurrentVersionRun_508c {
  strings:
    $key_508c = { 03 e3 [2] 27 ed [2] 0c c1 [2] 22 e3 [2] 36 f8 [2] 39 e2 [2] 27 ff [2] 25 fe [2] 3e f8 [2] 22 ff [2] 3e d0 }

  condition:
    any of them
}