rule TTP_XOR_QUAD_CurrentVersionRun_7c1e {
  strings:
    $key_7c1e = { 2f 71 [2] 0b 7f [2] 20 53 [2] 0e 71 [2] 1a 6a [2] 15 70 [2] 0b 6d [2] 09 6c [2] 12 6a [2] 0e 6d [2] 12 42 }

  condition:
    any of them
}