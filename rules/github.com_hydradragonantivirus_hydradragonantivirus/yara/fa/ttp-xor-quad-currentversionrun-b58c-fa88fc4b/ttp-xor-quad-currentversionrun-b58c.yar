rule TTP_XOR_QUAD_CurrentVersionRun_b58c {
  strings:
    $key_b58c = { e6 e3 [2] c2 ed [2] e9 c1 [2] c7 e3 [2] d3 f8 [2] dc e2 [2] c2 ff [2] c0 fe [2] db f8 [2] c7 ff [2] db d0 }

  condition:
    any of them
}