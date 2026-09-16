rule TTP_XOR_QUAD_CurrentVersionRun_792e {
  strings:
    $key_792e = { 2a 41 [2] 0e 4f [2] 25 63 [2] 0b 41 [2] 1f 5a [2] 10 40 [2] 0e 5d [2] 0c 5c [2] 17 5a [2] 0b 5d [2] 17 72 }

  condition:
    any of them
}