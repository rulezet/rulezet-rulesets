rule TTP_XOR_QUAD_CurrentVersionRun_77f2 {
  strings:
    $key_77f2 = { 24 9d [2] 00 93 [2] 2b bf [2] 05 9d [2] 11 86 [2] 1e 9c [2] 00 81 [2] 02 80 [2] 19 86 [2] 05 81 [2] 19 ae }

  condition:
    any of them
}