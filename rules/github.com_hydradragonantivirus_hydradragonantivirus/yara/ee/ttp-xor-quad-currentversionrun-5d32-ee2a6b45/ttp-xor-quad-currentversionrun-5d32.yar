rule TTP_XOR_QUAD_CurrentVersionRun_5d32 {
  strings:
    $key_5d32 = { 0e 5d [2] 2a 53 [2] 01 7f [2] 2f 5d [2] 3b 46 [2] 34 5c [2] 2a 41 [2] 28 40 [2] 33 46 [2] 2f 41 [2] 33 6e }

  condition:
    any of them
}