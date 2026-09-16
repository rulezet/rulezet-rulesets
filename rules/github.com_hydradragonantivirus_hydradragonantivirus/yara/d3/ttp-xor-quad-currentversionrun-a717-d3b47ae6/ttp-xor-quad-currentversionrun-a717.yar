rule TTP_XOR_QUAD_CurrentVersionRun_a717 {
  strings:
    $key_a717 = { f4 78 [2] d0 76 [2] fb 5a [2] d5 78 [2] c1 63 [2] ce 79 [2] d0 64 [2] d2 65 [2] c9 63 [2] d5 64 [2] c9 4b }

  condition:
    any of them
}