rule TTP_XOR_QUAD_CurrentVersionRun_a735 {
  strings:
    $key_a735 = { f4 5a [2] d0 54 [2] fb 78 [2] d5 5a [2] c1 41 [2] ce 5b [2] d0 46 [2] d2 47 [2] c9 41 [2] d5 46 [2] c9 69 }

  condition:
    any of them
}