rule TTP_XOR_QUAD_CurrentVersionRun_4502 {
  strings:
    $key_4502 = { 16 6d [2] 32 63 [2] 19 4f [2] 37 6d [2] 23 76 [2] 2c 6c [2] 32 71 [2] 30 70 [2] 2b 76 [2] 37 71 [2] 2b 5e }

  condition:
    any of them
}