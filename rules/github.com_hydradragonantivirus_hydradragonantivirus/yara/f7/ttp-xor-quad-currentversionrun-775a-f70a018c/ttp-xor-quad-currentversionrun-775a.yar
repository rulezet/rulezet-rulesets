rule TTP_XOR_QUAD_CurrentVersionRun_775a {
  strings:
    $key_775a = { 24 35 [2] 00 3b [2] 2b 17 [2] 05 35 [2] 11 2e [2] 1e 34 [2] 00 29 [2] 02 28 [2] 19 2e [2] 05 29 [2] 19 06 }

  condition:
    any of them
}