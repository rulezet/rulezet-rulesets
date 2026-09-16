rule TTP_XOR_QUAD_CurrentVersionRun_a719 {
  strings:
    $key_a719 = { f4 76 [2] d0 78 [2] fb 54 [2] d5 76 [2] c1 6d [2] ce 77 [2] d0 6a [2] d2 6b [2] c9 6d [2] d5 6a [2] c9 45 }

  condition:
    any of them
}