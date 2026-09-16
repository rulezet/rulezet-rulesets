rule TTP_XOR_QUAD_CurrentVersionRun_e18c {
  strings:
    $key_e18c = { b2 e3 [2] 96 ed [2] bd c1 [2] 93 e3 [2] 87 f8 [2] 88 e2 [2] 96 ff [2] 94 fe [2] 8f f8 [2] 93 ff [2] 8f d0 }

  condition:
    any of them
}