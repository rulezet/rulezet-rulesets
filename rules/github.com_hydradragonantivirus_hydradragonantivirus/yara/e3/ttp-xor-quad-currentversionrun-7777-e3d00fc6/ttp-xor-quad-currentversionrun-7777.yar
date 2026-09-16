rule TTP_XOR_QUAD_CurrentVersionRun_7777 {
  strings:
    $key_7777 = { 24 18 [2] 00 16 [2] 2b 3a [2] 05 18 [2] 11 03 [2] 1e 19 [2] 00 04 [2] 02 05 [2] 19 03 [2] 05 04 [2] 19 2b }

  condition:
    any of them
}