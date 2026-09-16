rule TTP_XOR_QUAD_CurrentVersionRun_0967 {
  strings:
    $key_0967 = { 5a 08 [2] 7e 06 [2] 55 2a [2] 7b 08 [2] 6f 13 [2] 60 09 [2] 7e 14 [2] 7c 15 [2] 67 13 [2] 7b 14 [2] 67 3b }

  condition:
    any of them
}