rule TTP_XOR_QUAD_CurrentVersionRun_a73b {
  strings:
    $key_a73b = { f4 54 [2] d0 5a [2] fb 76 [2] d5 54 [2] c1 4f [2] ce 55 [2] d0 48 [2] d2 49 [2] c9 4f [2] d5 48 [2] c9 67 }

  condition:
    any of them
}