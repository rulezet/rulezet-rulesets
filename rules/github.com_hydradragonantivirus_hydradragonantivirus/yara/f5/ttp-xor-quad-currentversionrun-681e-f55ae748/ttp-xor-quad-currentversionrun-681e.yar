rule TTP_XOR_QUAD_CurrentVersionRun_681e {
  strings:
    $key_681e = { 3b 71 [2] 1f 7f [2] 34 53 [2] 1a 71 [2] 0e 6a [2] 01 70 [2] 1f 6d [2] 1d 6c [2] 06 6a [2] 1a 6d [2] 06 42 }

  condition:
    any of them
}