rule TTP_XOR_QUAD_CurrentVersionRun_2972 {
  strings:
    $key_2972 = { 7a 1d [2] 5e 13 [2] 75 3f [2] 5b 1d [2] 4f 06 [2] 40 1c [2] 5e 01 [2] 5c 00 [2] 47 06 [2] 5b 01 [2] 47 2e }

  condition:
    any of them
}