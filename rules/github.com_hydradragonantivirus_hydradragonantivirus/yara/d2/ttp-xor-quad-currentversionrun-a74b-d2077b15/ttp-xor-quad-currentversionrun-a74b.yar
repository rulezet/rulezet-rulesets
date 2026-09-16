rule TTP_XOR_QUAD_CurrentVersionRun_a74b {
  strings:
    $key_a74b = { f4 24 [2] d0 2a [2] fb 06 [2] d5 24 [2] c1 3f [2] ce 25 [2] d0 38 [2] d2 39 [2] c9 3f [2] d5 38 [2] c9 17 }

  condition:
    any of them
}