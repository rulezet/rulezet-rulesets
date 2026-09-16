rule TTP_XOR_QUAD_CurrentVersionRun_009e {
  strings:
    $key_009e = { 53 f1 [2] 77 ff [2] 5c d3 [2] 72 f1 [2] 66 ea [2] 69 f0 [2] 77 ed [2] 75 ec [2] 6e ea [2] 72 ed [2] 6e c2 }

  condition:
    any of them
}