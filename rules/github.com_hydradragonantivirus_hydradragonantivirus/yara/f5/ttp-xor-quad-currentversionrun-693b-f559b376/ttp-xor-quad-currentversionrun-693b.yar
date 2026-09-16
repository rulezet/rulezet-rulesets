rule TTP_XOR_QUAD_CurrentVersionRun_693b {
  strings:
    $key_693b = { 3a 54 [2] 1e 5a [2] 35 76 [2] 1b 54 [2] 0f 4f [2] 00 55 [2] 1e 48 [2] 1c 49 [2] 07 4f [2] 1b 48 [2] 07 67 }

  condition:
    any of them
}