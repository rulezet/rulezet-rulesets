rule TTP_XOR_QUAD_CurrentVersionRun_3072 {
  strings:
    $key_3072 = { 63 1d [2] 47 13 [2] 6c 3f [2] 42 1d [2] 56 06 [2] 59 1c [2] 47 01 [2] 45 00 [2] 5e 06 [2] 42 01 [2] 5e 2e }

  condition:
    any of them
}