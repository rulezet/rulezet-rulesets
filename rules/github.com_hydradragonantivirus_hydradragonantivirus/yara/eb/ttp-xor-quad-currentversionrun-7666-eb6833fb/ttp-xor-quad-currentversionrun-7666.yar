rule TTP_XOR_QUAD_CurrentVersionRun_7666 {
  strings:
    $key_7666 = { 25 09 [2] 01 07 [2] 2a 2b [2] 04 09 [2] 10 12 [2] 1f 08 [2] 01 15 [2] 03 14 [2] 18 12 [2] 04 15 [2] 18 3a }

  condition:
    any of them
}