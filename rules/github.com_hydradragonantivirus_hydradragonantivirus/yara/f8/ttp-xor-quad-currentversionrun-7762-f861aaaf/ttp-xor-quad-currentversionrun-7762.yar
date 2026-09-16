rule TTP_XOR_QUAD_CurrentVersionRun_7762 {
  strings:
    $key_7762 = { 24 0d [2] 00 03 [2] 2b 2f [2] 05 0d [2] 11 16 [2] 1e 0c [2] 00 11 [2] 02 10 [2] 19 16 [2] 05 11 [2] 19 3e }

  condition:
    any of them
}