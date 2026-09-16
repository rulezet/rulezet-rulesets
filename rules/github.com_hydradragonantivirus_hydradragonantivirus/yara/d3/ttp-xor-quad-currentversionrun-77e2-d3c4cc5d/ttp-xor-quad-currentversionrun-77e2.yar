rule TTP_XOR_QUAD_CurrentVersionRun_77e2 {
  strings:
    $key_77e2 = { 24 8d [2] 00 83 [2] 2b af [2] 05 8d [2] 11 96 [2] 1e 8c [2] 00 91 [2] 02 90 [2] 19 96 [2] 05 91 [2] 19 be }

  condition:
    any of them
}