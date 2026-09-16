rule TTP_XOR_QUAD_CurrentVersionRun_2f8c {
  strings:
    $key_2f8c = { 7c e3 [2] 58 ed [2] 73 c1 [2] 5d e3 [2] 49 f8 [2] 46 e2 [2] 58 ff [2] 5a fe [2] 41 f8 [2] 5d ff [2] 41 d0 }

  condition:
    any of them
}