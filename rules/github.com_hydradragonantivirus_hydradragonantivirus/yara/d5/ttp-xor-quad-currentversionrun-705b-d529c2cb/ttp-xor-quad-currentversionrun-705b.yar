rule TTP_XOR_QUAD_CurrentVersionRun_705b {
  strings:
    $key_705b = { 23 34 [2] 07 3a [2] 2c 16 [2] 02 34 [2] 16 2f [2] 19 35 [2] 07 28 [2] 05 29 [2] 1e 2f [2] 02 28 [2] 1e 07 }

  condition:
    any of them
}