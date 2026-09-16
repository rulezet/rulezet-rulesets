rule TTP_XOR_QUAD_CurrentVersionRun_bbf1 {
  strings:
    $key_bbf1 = { e8 9e [2] cc 90 [2] e7 bc [2] c9 9e [2] dd 85 [2] d2 9f [2] cc 82 [2] ce 83 [2] d5 85 [2] c9 82 [2] d5 ad }

  condition:
    any of them
}