rule TTP_XOR_QUAD_CurrentVersionRun_763e {
  strings:
    $key_763e = { 25 51 [2] 01 5f [2] 2a 73 [2] 04 51 [2] 10 4a [2] 1f 50 [2] 01 4d [2] 03 4c [2] 18 4a [2] 04 4d [2] 18 62 }

  condition:
    any of them
}