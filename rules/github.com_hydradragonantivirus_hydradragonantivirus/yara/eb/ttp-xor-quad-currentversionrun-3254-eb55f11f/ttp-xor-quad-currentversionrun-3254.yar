rule TTP_XOR_QUAD_CurrentVersionRun_3254 {
  strings:
    $key_3254 = { 61 3b [2] 45 35 [2] 6e 19 [2] 40 3b [2] 54 20 [2] 5b 3a [2] 45 27 [2] 47 26 [2] 5c 20 [2] 40 27 [2] 5c 08 }

  condition:
    any of them
}