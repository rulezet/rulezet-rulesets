rule TTP_XOR_QUAD_CurrentVersionRun_2b27 {
  strings:
    $key_2b27 = { 78 48 [2] 5c 46 [2] 77 6a [2] 59 48 [2] 4d 53 [2] 42 49 [2] 5c 54 [2] 5e 55 [2] 45 53 [2] 59 54 [2] 45 7b }

  condition:
    any of them
}