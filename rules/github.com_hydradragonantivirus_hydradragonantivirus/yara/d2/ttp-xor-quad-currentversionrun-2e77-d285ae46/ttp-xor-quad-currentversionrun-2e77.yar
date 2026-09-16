rule TTP_XOR_QUAD_CurrentVersionRun_2e77 {
  strings:
    $key_2e77 = { 7d 18 [2] 59 16 [2] 72 3a [2] 5c 18 [2] 48 03 [2] 47 19 [2] 59 04 [2] 5b 05 [2] 40 03 [2] 5c 04 [2] 40 2b }

  condition:
    any of them
}