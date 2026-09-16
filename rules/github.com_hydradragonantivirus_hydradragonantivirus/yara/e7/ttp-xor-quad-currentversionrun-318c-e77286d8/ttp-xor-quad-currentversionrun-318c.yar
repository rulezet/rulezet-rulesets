rule TTP_XOR_QUAD_CurrentVersionRun_318c {
  strings:
    $key_318c = { 62 e3 [2] 46 ed [2] 6d c1 [2] 43 e3 [2] 57 f8 [2] 58 e2 [2] 46 ff [2] 44 fe [2] 5f f8 [2] 43 ff [2] 5f d0 }

  condition:
    any of them
}