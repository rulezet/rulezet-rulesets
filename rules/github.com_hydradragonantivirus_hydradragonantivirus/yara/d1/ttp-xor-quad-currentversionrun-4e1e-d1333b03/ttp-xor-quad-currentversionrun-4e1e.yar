rule TTP_XOR_QUAD_CurrentVersionRun_4e1e {
  strings:
    $key_4e1e = { 1d 71 [2] 39 7f [2] 12 53 [2] 3c 71 [2] 28 6a [2] 27 70 [2] 39 6d [2] 3b 6c [2] 20 6a [2] 3c 6d [2] 20 42 }

  condition:
    any of them
}