rule TTP_XOR_QUAD_CurrentVersionRun_028c {
  strings:
    $key_028c = { 51 e3 [2] 75 ed [2] 5e c1 [2] 70 e3 [2] 64 f8 [2] 6b e2 [2] 75 ff [2] 77 fe [2] 6c f8 [2] 70 ff [2] 6c d0 }

  condition:
    any of them
}