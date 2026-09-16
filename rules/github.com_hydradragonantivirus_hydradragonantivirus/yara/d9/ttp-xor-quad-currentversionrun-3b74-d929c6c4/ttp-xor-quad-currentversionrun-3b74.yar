rule TTP_XOR_QUAD_CurrentVersionRun_3b74 {
  strings:
    $key_3b74 = { 68 1b [2] 4c 15 [2] 67 39 [2] 49 1b [2] 5d 00 [2] 52 1a [2] 4c 07 [2] 4e 06 [2] 55 00 [2] 49 07 [2] 55 28 }

  condition:
    any of them
}