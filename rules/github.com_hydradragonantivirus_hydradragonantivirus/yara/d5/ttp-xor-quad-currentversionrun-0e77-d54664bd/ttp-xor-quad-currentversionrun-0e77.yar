rule TTP_XOR_QUAD_CurrentVersionRun_0e77 {
  strings:
    $key_0e77 = { 5d 18 [2] 79 16 [2] 52 3a [2] 7c 18 [2] 68 03 [2] 67 19 [2] 79 04 [2] 7b 05 [2] 60 03 [2] 7c 04 [2] 60 2b }

  condition:
    any of them
}