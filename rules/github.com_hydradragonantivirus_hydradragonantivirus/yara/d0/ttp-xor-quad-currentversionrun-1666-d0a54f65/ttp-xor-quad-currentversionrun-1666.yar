rule TTP_XOR_QUAD_CurrentVersionRun_1666 {
  strings:
    $key_1666 = { 45 09 [2] 61 07 [2] 4a 2b [2] 64 09 [2] 70 12 [2] 7f 08 [2] 61 15 [2] 63 14 [2] 78 12 [2] 64 15 [2] 78 3a }

  condition:
    any of them
}