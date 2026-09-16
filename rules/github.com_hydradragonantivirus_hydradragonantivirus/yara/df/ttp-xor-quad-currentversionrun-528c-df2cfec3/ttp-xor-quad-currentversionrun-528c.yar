rule TTP_XOR_QUAD_CurrentVersionRun_528c {
  strings:
    $key_528c = { 01 e3 [2] 25 ed [2] 0e c1 [2] 20 e3 [2] 34 f8 [2] 3b e2 [2] 25 ff [2] 27 fe [2] 3c f8 [2] 20 ff [2] 3c d0 }

  condition:
    any of them
}