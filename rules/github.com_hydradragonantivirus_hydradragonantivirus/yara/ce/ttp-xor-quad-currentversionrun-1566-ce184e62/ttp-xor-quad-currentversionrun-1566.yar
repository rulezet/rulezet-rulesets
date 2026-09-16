rule TTP_XOR_QUAD_CurrentVersionRun_1566 {
  strings:
    $key_1566 = { 46 09 [2] 62 07 [2] 49 2b [2] 67 09 [2] 73 12 [2] 7c 08 [2] 62 15 [2] 60 14 [2] 7b 12 [2] 67 15 [2] 7b 3a }

  condition:
    any of them
}