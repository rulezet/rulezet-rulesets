rule TTP_XOR_QUAD_CurrentVersionRun_72e4 {
  strings:
    $key_72e4 = { 21 8b [2] 05 85 [2] 2e a9 [2] 00 8b [2] 14 90 [2] 1b 8a [2] 05 97 [2] 07 96 [2] 1c 90 [2] 00 97 [2] 1c b8 }

  condition:
    any of them
}