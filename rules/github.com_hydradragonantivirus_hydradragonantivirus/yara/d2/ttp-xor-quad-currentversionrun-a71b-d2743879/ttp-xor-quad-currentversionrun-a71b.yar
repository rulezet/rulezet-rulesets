rule TTP_XOR_QUAD_CurrentVersionRun_a71b {
  strings:
    $key_a71b = { f4 74 [2] d0 7a [2] fb 56 [2] d5 74 [2] c1 6f [2] ce 75 [2] d0 68 [2] d2 69 [2] c9 6f [2] d5 68 [2] c9 47 }

  condition:
    any of them
}