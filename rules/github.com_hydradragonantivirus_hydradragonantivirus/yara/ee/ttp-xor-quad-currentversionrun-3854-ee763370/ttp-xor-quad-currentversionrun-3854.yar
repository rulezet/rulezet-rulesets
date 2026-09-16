rule TTP_XOR_QUAD_CurrentVersionRun_3854 {
  strings:
    $key_3854 = { 6b 3b [2] 4f 35 [2] 64 19 [2] 4a 3b [2] 5e 20 [2] 51 3a [2] 4f 27 [2] 4d 26 [2] 56 20 [2] 4a 27 [2] 56 08 }

  condition:
    any of them
}