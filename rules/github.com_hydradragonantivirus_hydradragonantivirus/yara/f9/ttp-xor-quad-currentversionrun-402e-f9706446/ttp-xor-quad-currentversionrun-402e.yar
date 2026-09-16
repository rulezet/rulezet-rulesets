rule TTP_XOR_QUAD_CurrentVersionRun_402e {
  strings:
    $key_402e = { 13 41 [2] 37 4f [2] 1c 63 [2] 32 41 [2] 26 5a [2] 29 40 [2] 37 5d [2] 35 5c [2] 2e 5a [2] 32 5d [2] 2e 72 }

  condition:
    any of them
}