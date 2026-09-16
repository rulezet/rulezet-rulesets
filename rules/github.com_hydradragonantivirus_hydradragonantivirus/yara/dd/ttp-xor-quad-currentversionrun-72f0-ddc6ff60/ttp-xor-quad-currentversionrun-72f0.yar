rule TTP_XOR_QUAD_CurrentVersionRun_72f0 {
  strings:
    $key_72f0 = { 21 9f [2] 05 91 [2] 2e bd [2] 00 9f [2] 14 84 [2] 1b 9e [2] 05 83 [2] 07 82 [2] 1c 84 [2] 00 83 [2] 1c ac }

  condition:
    any of them
}