rule TTP_XOR_QUAD_CurrentVersionRun_5917 {
  strings:
    $key_5917 = { 0a 78 [2] 2e 76 [2] 05 5a [2] 2b 78 [2] 3f 63 [2] 30 79 [2] 2e 64 [2] 2c 65 [2] 37 63 [2] 2b 64 [2] 37 4b }

  condition:
    any of them
}