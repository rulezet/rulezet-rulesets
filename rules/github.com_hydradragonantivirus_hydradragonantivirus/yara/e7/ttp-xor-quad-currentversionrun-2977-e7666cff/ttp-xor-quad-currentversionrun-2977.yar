rule TTP_XOR_QUAD_CurrentVersionRun_2977 {
  strings:
    $key_2977 = { 7a 18 [2] 5e 16 [2] 75 3a [2] 5b 18 [2] 4f 03 [2] 40 19 [2] 5e 04 [2] 5c 05 [2] 47 03 [2] 5b 04 [2] 47 2b }

  condition:
    any of them
}