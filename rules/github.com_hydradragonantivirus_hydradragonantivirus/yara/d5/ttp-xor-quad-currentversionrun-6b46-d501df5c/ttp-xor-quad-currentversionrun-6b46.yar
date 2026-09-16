rule TTP_XOR_QUAD_CurrentVersionRun_6b46 {
  strings:
    $key_6b46 = { 38 29 [2] 1c 27 [2] 37 0b [2] 19 29 [2] 0d 32 [2] 02 28 [2] 1c 35 [2] 1e 34 [2] 05 32 [2] 19 35 [2] 05 1a }

  condition:
    any of them
}