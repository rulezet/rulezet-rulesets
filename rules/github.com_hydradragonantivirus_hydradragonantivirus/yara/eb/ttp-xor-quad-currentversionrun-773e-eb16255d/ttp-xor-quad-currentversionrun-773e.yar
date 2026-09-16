rule TTP_XOR_QUAD_CurrentVersionRun_773e {
  strings:
    $key_773e = { 24 51 [2] 00 5f [2] 2b 73 [2] 05 51 [2] 11 4a [2] 1e 50 [2] 00 4d [2] 02 4c [2] 19 4a [2] 05 4d [2] 19 62 }

  condition:
    any of them
}