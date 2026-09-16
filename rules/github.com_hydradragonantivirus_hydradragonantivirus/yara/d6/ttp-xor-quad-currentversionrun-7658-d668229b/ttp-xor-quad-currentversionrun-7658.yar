rule TTP_XOR_QUAD_CurrentVersionRun_7658 {
  strings:
    $key_7658 = { 25 37 [2] 01 39 [2] 2a 15 [2] 04 37 [2] 10 2c [2] 1f 36 [2] 01 2b [2] 03 2a [2] 18 2c [2] 04 2b [2] 18 04 }

  condition:
    any of them
}