rule TTP_XOR_QUAD_CurrentVersionRun_a769 {
  strings:
    $key_a769 = { f4 06 [2] d0 08 [2] fb 24 [2] d5 06 [2] c1 1d [2] ce 07 [2] d0 1a [2] d2 1b [2] c9 1d [2] d5 1a [2] c9 35 }

  condition:
    any of them
}