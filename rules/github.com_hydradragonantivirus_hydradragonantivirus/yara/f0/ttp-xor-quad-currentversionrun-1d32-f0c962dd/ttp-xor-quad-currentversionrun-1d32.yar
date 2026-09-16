rule TTP_XOR_QUAD_CurrentVersionRun_1d32 {
  strings:
    $key_1d32 = { 4e 5d [2] 6a 53 [2] 41 7f [2] 6f 5d [2] 7b 46 [2] 74 5c [2] 6a 41 [2] 68 40 [2] 73 46 [2] 6f 41 [2] 73 6e }

  condition:
    any of them
}