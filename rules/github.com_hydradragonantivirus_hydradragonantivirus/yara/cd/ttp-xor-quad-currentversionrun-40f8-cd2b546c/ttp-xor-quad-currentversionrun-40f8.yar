rule TTP_XOR_QUAD_CurrentVersionRun_40f8 {
  strings:
    $key_40f8 = { 13 97 [2] 37 99 [2] 1c b5 [2] 32 97 [2] 26 8c [2] 29 96 [2] 37 8b [2] 35 8a [2] 2e 8c [2] 32 8b [2] 2e a4 }

  condition:
    any of them
}