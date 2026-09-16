rule TTP_XOR_QUAD_CurrentVersionRun_f09e {
  strings:
    $key_f09e = { a3 f1 [2] 87 ff [2] ac d3 [2] 82 f1 [2] 96 ea [2] 99 f0 [2] 87 ed [2] 85 ec [2] 9e ea [2] 82 ed [2] 9e c2 }

  condition:
    any of them
}