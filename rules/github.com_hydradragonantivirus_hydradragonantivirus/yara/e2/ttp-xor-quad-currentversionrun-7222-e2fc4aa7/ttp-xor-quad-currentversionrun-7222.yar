rule TTP_XOR_QUAD_CurrentVersionRun_7222 {
  strings:
    $key_7222 = { 21 4d [2] 05 43 [2] 2e 6f [2] 00 4d [2] 14 56 [2] 1b 4c [2] 05 51 [2] 07 50 [2] 1c 56 [2] 00 51 [2] 1c 7e }

  condition:
    any of them
}