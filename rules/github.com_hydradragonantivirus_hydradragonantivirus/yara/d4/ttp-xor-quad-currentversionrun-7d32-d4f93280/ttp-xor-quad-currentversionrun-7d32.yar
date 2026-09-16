rule TTP_XOR_QUAD_CurrentVersionRun_7d32 {
  strings:
    $key_7d32 = { 2e 5d [2] 0a 53 [2] 21 7f [2] 0f 5d [2] 1b 46 [2] 14 5c [2] 0a 41 [2] 08 40 [2] 13 46 [2] 0f 41 [2] 13 6e }

  condition:
    any of them
}