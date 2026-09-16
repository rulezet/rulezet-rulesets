rule TTP_XOR_QUAD_CurrentVersionRun_6c1e {
  strings:
    $key_6c1e = { 3f 71 [2] 1b 7f [2] 30 53 [2] 1e 71 [2] 0a 6a [2] 05 70 [2] 1b 6d [2] 19 6c [2] 02 6a [2] 1e 6d [2] 02 42 }

  condition:
    any of them
}