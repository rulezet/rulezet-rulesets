rule TTP_XOR_QUAD_CurrentVersionRun_7262 {
  strings:
    $key_7262 = { 21 0d [2] 05 03 [2] 2e 2f [2] 00 0d [2] 14 16 [2] 1b 0c [2] 05 11 [2] 07 10 [2] 1c 16 [2] 00 11 [2] 1c 3e }

  condition:
    any of them
}