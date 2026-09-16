rule TTP_XOR_QUAD_CurrentVersionRun_7732 {
  strings:
    $key_7732 = { 24 5d [2] 00 53 [2] 2b 7f [2] 05 5d [2] 11 46 [2] 1e 5c [2] 00 41 [2] 02 40 [2] 19 46 [2] 05 41 [2] 19 6e }

  condition:
    any of them
}