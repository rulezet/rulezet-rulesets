rule TTP_XOR_QUAD_CurrentVersionRun_671e {
  strings:
    $key_671e = { 34 71 [2] 10 7f [2] 3b 53 [2] 15 71 [2] 01 6a [2] 0e 70 [2] 10 6d [2] 12 6c [2] 09 6a [2] 15 6d [2] 09 42 }

  condition:
    any of them
}