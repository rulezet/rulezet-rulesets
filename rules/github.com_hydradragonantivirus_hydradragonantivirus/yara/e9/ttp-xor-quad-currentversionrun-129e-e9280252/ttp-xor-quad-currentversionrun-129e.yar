rule TTP_XOR_QUAD_CurrentVersionRun_129e {
  strings:
    $key_129e = { 41 f1 [2] 65 ff [2] 4e d3 [2] 60 f1 [2] 74 ea [2] 7b f0 [2] 65 ed [2] 67 ec [2] 7c ea [2] 60 ed [2] 7c c2 }

  condition:
    any of them
}