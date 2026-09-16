rule TTP_XOR_QUAD_CurrentVersionRun_4726 {
  strings:
    $key_4726 = { 14 49 [2] 30 47 [2] 1b 6b [2] 35 49 [2] 21 52 [2] 2e 48 [2] 30 55 [2] 32 54 [2] 29 52 [2] 35 55 [2] 29 7a }

  condition:
    any of them
}