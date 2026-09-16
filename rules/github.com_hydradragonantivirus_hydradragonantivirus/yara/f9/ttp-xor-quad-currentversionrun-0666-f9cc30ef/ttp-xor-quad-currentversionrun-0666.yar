rule TTP_XOR_QUAD_CurrentVersionRun_0666 {
  strings:
    $key_0666 = { 55 09 [2] 71 07 [2] 5a 2b [2] 74 09 [2] 60 12 [2] 6f 08 [2] 71 15 [2] 73 14 [2] 68 12 [2] 74 15 [2] 68 3a }

  condition:
    any of them
}