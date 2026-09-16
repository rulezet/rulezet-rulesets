rule TTP_XOR_QUAD_CurrentVersionRun_0a66 {
  strings:
    $key_0a66 = { 59 09 [2] 7d 07 [2] 56 2b [2] 78 09 [2] 6c 12 [2] 63 08 [2] 7d 15 [2] 7f 14 [2] 64 12 [2] 78 15 [2] 64 3a }

  condition:
    any of them
}