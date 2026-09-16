rule TTP_XOR_QUAD_CurrentVersionRun_3054 {
  strings:
    $key_3054 = { 63 3b [2] 47 35 [2] 6c 19 [2] 42 3b [2] 56 20 [2] 59 3a [2] 47 27 [2] 45 26 [2] 5e 20 [2] 42 27 [2] 5e 08 }

  condition:
    any of them
}