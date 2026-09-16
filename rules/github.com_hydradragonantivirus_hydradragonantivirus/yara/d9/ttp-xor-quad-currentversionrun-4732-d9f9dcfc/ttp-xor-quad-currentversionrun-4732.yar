rule TTP_XOR_QUAD_CurrentVersionRun_4732 {
  strings:
    $key_4732 = { 14 5d [2] 30 53 [2] 1b 7f [2] 35 5d [2] 21 46 [2] 2e 5c [2] 30 41 [2] 32 40 [2] 29 46 [2] 35 41 [2] 29 6e }

  condition:
    any of them
}