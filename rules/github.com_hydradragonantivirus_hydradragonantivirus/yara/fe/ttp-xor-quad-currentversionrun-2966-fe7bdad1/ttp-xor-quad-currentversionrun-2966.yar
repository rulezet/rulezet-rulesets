rule TTP_XOR_QUAD_CurrentVersionRun_2966 {
  strings:
    $key_2966 = { 7a 09 [2] 5e 07 [2] 75 2b [2] 5b 09 [2] 4f 12 [2] 40 08 [2] 5e 15 [2] 5c 14 [2] 47 12 [2] 5b 15 [2] 47 3a }

  condition:
    any of them
}