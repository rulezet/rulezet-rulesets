rule TTP_XOR_QUAD_CurrentVersionRun_218c {
  strings:
    $key_218c = { 72 e3 [2] 56 ed [2] 7d c1 [2] 53 e3 [2] 47 f8 [2] 48 e2 [2] 56 ff [2] 54 fe [2] 4f f8 [2] 53 ff [2] 4f d0 }

  condition:
    any of them
}