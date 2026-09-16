rule TTP_XOR_QUAD_CurrentVersionRun_4e2e {
  strings:
    $key_4e2e = { 1d 41 [2] 39 4f [2] 12 63 [2] 3c 41 [2] 28 5a [2] 27 40 [2] 39 5d [2] 3b 5c [2] 20 5a [2] 3c 5d [2] 20 72 }

  condition:
    any of them
}