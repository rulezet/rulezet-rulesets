rule TTP_XOR_QUAD_CurrentVersionRun_ef66 {
  strings:
    $key_ef66 = { bc 09 [2] 98 07 [2] b3 2b [2] 9d 09 [2] 89 12 [2] 86 08 [2] 98 15 [2] 9a 14 [2] 81 12 [2] 9d 15 [2] 81 3a }

  condition:
    any of them
}