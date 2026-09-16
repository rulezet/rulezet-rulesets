rule TTP_XOR_QUAD_CurrentVersionRun_732e {
  strings:
    $key_732e = { 20 41 [2] 04 4f [2] 2f 63 [2] 01 41 [2] 15 5a [2] 1a 40 [2] 04 5d [2] 06 5c [2] 1d 5a [2] 01 5d [2] 1d 72 }

  condition:
    any of them
}