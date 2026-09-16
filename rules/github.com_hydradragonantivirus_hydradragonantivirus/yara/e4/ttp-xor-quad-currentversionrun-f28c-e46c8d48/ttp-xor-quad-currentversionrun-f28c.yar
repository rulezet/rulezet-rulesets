rule TTP_XOR_QUAD_CurrentVersionRun_f28c {
  strings:
    $key_f28c = { a1 e3 [2] 85 ed [2] ae c1 [2] 80 e3 [2] 94 f8 [2] 9b e2 [2] 85 ff [2] 87 fe [2] 9c f8 [2] 80 ff [2] 9c d0 }

  condition:
    any of them
}