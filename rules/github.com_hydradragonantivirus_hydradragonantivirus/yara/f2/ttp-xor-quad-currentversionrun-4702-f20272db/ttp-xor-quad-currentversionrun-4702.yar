rule TTP_XOR_QUAD_CurrentVersionRun_4702 {
  strings:
    $key_4702 = { 14 6d [2] 30 63 [2] 1b 4f [2] 35 6d [2] 21 76 [2] 2e 6c [2] 30 71 [2] 32 70 [2] 29 76 [2] 35 71 [2] 29 5e }

  condition:
    any of them
}