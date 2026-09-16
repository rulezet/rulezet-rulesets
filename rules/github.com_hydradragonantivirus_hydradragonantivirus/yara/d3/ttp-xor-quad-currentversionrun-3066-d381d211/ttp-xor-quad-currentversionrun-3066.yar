rule TTP_XOR_QUAD_CurrentVersionRun_3066 {
  strings:
    $key_3066 = { 63 09 [2] 47 07 [2] 6c 2b [2] 42 09 [2] 56 12 [2] 59 08 [2] 47 15 [2] 45 14 [2] 5e 12 [2] 42 15 [2] 5e 3a }

  condition:
    any of them
}