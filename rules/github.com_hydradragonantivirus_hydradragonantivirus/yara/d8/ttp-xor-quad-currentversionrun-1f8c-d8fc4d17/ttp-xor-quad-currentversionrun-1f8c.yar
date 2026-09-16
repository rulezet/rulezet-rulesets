rule TTP_XOR_QUAD_CurrentVersionRun_1f8c {
  strings:
    $key_1f8c = { 4c e3 [2] 68 ed [2] 43 c1 [2] 6d e3 [2] 79 f8 [2] 76 e2 [2] 68 ff [2] 6a fe [2] 71 f8 [2] 6d ff [2] 71 d0 }

  condition:
    any of them
}