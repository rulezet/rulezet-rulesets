rule TTP_XOR_QUAD_CurrentVersionRun_e1e5 {
  strings:
    $key_e1e5 = { b2 8a [2] 96 84 [2] bd a8 [2] 93 8a [2] 87 91 [2] 88 8b [2] 96 96 [2] 94 97 [2] 8f 91 [2] 93 96 [2] 8f b9 }

  condition:
    any of them
}