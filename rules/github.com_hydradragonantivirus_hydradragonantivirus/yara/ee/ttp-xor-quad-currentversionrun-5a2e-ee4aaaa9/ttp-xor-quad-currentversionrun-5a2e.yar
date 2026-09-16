rule TTP_XOR_QUAD_CurrentVersionRun_5a2e {
  strings:
    $key_5a2e = { 09 41 [2] 2d 4f [2] 06 63 [2] 28 41 [2] 3c 5a [2] 33 40 [2] 2d 5d [2] 2f 5c [2] 34 5a [2] 28 5d [2] 34 72 }

  condition:
    any of them
}