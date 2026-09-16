rule TTP_XOR_QUAD_CurrentVersionRun_6572 {
  strings:
    $key_6572 = { 36 1d [2] 12 13 [2] 39 3f [2] 17 1d [2] 03 06 [2] 0c 1c [2] 12 01 [2] 10 00 [2] 0b 06 [2] 17 01 [2] 0b 2e }

  condition:
    any of them
}