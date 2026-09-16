rule TTP_XOR_QUAD_CurrentVersionRun_a773 {
  strings:
    $key_a773 = { f4 1c [2] d0 12 [2] fb 3e [2] d5 1c [2] c1 07 [2] ce 1d [2] d0 00 [2] d2 01 [2] c9 07 [2] d5 00 [2] c9 2f }

  condition:
    any of them
}