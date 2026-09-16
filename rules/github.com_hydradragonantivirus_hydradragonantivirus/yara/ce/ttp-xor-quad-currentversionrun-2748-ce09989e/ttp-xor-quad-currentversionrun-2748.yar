rule TTP_XOR_QUAD_CurrentVersionRun_2748 {
  strings:
    $key_2748 = { 74 27 [2] 50 29 [2] 7b 05 [2] 55 27 [2] 41 3c [2] 4e 26 [2] 50 3b [2] 52 3a [2] 49 3c [2] 55 3b [2] 49 14 }

  condition:
    any of them
}