rule TTP_XOR_QUAD_CurrentVersionRun_a715 {
  strings:
    $key_a715 = { f4 7a [2] d0 74 [2] fb 58 [2] d5 7a [2] c1 61 [2] ce 7b [2] d0 66 [2] d2 67 [2] c9 61 [2] d5 66 [2] c9 49 }

  condition:
    any of them
}