rule TTP_XOR_QUAD_CurrentVersionRun_6d76 {
  strings:
    $key_6d76 = { 3e 19 [2] 1a 17 [2] 31 3b [2] 1f 19 [2] 0b 02 [2] 04 18 [2] 1a 05 [2] 18 04 [2] 03 02 [2] 1f 05 [2] 03 2a }

  condition:
    any of them
}