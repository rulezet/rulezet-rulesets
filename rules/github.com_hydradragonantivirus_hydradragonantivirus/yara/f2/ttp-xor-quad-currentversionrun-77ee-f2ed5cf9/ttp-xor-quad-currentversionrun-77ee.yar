rule TTP_XOR_QUAD_CurrentVersionRun_77ee {
  strings:
    $key_77ee = { 24 81 [2] 00 8f [2] 2b a3 [2] 05 81 [2] 11 9a [2] 1e 80 [2] 00 9d [2] 02 9c [2] 19 9a [2] 05 9d [2] 19 b2 }

  condition:
    any of them
}