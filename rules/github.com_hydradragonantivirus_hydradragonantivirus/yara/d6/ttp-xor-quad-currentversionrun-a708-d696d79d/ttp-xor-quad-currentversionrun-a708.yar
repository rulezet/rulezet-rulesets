rule TTP_XOR_QUAD_CurrentVersionRun_a708 {
  strings:
    $key_a708 = { f4 67 [2] d0 69 [2] fb 45 [2] d5 67 [2] c1 7c [2] ce 66 [2] d0 7b [2] d2 7a [2] c9 7c [2] d5 7b [2] c9 54 }

  condition:
    any of them
}