rule TTP_XOR_QUAD_CurrentVersionRun_4027 {
  strings:
    $key_4027 = { 13 48 [2] 37 46 [2] 1c 6a [2] 32 48 [2] 26 53 [2] 29 49 [2] 37 54 [2] 35 55 [2] 2e 53 [2] 32 54 [2] 2e 7b }

  condition:
    any of them
}