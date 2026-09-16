rule TTP_XOR_QUAD_CurrentVersionRun_0a67 {
  strings:
    $key_0a67 = { 59 08 [2] 7d 06 [2] 56 2a [2] 78 08 [2] 6c 13 [2] 63 09 [2] 7d 14 [2] 7f 15 [2] 64 13 [2] 78 14 [2] 64 3b }

  condition:
    any of them
}