rule TTP_XOR_QUAD_CurrentVersionRun_1668 {
  strings:
    $key_1668 = { 45 07 [2] 61 09 [2] 4a 25 [2] 64 07 [2] 70 1c [2] 7f 06 [2] 61 1b [2] 63 1a [2] 78 1c [2] 64 1b [2] 78 34 }

  condition:
    any of them
}