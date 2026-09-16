rule TTP_XOR_QUAD_CurrentVersionRun_777b {
  strings:
    $key_777b = { 24 14 [2] 00 1a [2] 2b 36 [2] 05 14 [2] 11 0f [2] 1e 15 [2] 00 08 [2] 02 09 [2] 19 0f [2] 05 08 [2] 19 27 }

  condition:
    any of them
}