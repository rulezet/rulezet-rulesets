rule TTP_XOR_QUAD_CurrentVersionRun_7772 {
  strings:
    $key_7772 = { 24 1d [2] 00 13 [2] 2b 3f [2] 05 1d [2] 11 06 [2] 1e 1c [2] 00 01 [2] 02 00 [2] 19 06 [2] 05 01 [2] 19 2e }

  condition:
    any of them
}