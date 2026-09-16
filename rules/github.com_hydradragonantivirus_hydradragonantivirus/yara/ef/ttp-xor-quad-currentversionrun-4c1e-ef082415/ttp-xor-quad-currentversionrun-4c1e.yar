rule TTP_XOR_QUAD_CurrentVersionRun_4c1e {
  strings:
    $key_4c1e = { 1f 71 [2] 3b 7f [2] 10 53 [2] 3e 71 [2] 2a 6a [2] 25 70 [2] 3b 6d [2] 39 6c [2] 22 6a [2] 3e 6d [2] 22 42 }

  condition:
    any of them
}