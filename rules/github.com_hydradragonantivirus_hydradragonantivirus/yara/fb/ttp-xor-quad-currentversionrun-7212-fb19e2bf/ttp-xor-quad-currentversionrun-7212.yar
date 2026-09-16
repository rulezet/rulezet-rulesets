rule TTP_XOR_QUAD_CurrentVersionRun_7212 {
  strings:
    $key_7212 = { 21 7d [2] 05 73 [2] 2e 5f [2] 00 7d [2] 14 66 [2] 1b 7c [2] 05 61 [2] 07 60 [2] 1c 66 [2] 00 61 [2] 1c 4e }

  condition:
    any of them
}