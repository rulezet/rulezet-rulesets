rule TTP_XOR_QUAD_CurrentVersionRun_706b {
  strings:
    $key_706b = { 23 04 [2] 07 0a [2] 2c 26 [2] 02 04 [2] 16 1f [2] 19 05 [2] 07 18 [2] 05 19 [2] 1e 1f [2] 02 18 [2] 1e 37 }

  condition:
    any of them
}