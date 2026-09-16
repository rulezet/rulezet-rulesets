rule TTP_XOR_QUAD_CurrentVersionRun_a7f8 {
  strings:
    $key_a7f8 = { f4 97 [2] d0 99 [2] fb b5 [2] d5 97 [2] c1 8c [2] ce 96 [2] d0 8b [2] d2 8a [2] c9 8c [2] d5 8b [2] c9 a4 }

  condition:
    any of them
}