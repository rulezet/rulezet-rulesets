rule TTP_XOR_QUAD_CurrentVersionRun_5232 {
  strings:
    $key_5232 = { 01 5d [2] 25 53 [2] 0e 7f [2] 20 5d [2] 34 46 [2] 3b 5c [2] 25 41 [2] 27 40 [2] 3c 46 [2] 20 41 [2] 3c 6e }

  condition:
    any of them
}