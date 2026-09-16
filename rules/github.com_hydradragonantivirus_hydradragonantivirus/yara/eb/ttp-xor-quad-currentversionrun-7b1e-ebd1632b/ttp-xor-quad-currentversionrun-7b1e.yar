rule TTP_XOR_QUAD_CurrentVersionRun_7b1e {
  strings:
    $key_7b1e = { 28 71 [2] 0c 7f [2] 27 53 [2] 09 71 [2] 1d 6a [2] 12 70 [2] 0c 6d [2] 0e 6c [2] 15 6a [2] 09 6d [2] 15 42 }

  condition:
    any of them
}