rule TTP_XOR_QUAD_CurrentVersionRun_109e {
  strings:
    $key_109e = { 43 f1 [2] 67 ff [2] 4c d3 [2] 62 f1 [2] 76 ea [2] 79 f0 [2] 67 ed [2] 65 ec [2] 7e ea [2] 62 ed [2] 7e c2 }

  condition:
    any of them
}