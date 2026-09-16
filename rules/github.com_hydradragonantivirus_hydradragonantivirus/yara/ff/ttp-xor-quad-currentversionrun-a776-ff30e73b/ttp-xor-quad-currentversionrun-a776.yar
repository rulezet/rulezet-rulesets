rule TTP_XOR_QUAD_CurrentVersionRun_a776 {
  strings:
    $key_a776 = { f4 19 [2] d0 17 [2] fb 3b [2] d5 19 [2] c1 02 [2] ce 18 [2] d0 05 [2] d2 04 [2] c9 02 [2] d5 05 [2] c9 2a }

  condition:
    any of them
}