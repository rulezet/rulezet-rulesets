rule TTP_XOR_QUAD_CurrentVersionRun_e1f1 {
  strings:
    $key_e1f1 = { b2 9e [2] 96 90 [2] bd bc [2] 93 9e [2] 87 85 [2] 88 9f [2] 96 82 [2] 94 83 [2] 8f 85 [2] 93 82 [2] 8f ad }

  condition:
    any of them
}