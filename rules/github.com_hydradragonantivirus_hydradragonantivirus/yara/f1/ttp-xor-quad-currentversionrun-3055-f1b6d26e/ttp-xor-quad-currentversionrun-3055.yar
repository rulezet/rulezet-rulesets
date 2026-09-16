rule TTP_XOR_QUAD_CurrentVersionRun_3055 {
  strings:
    $key_3055 = { 63 3a [2] 47 34 [2] 6c 18 [2] 42 3a [2] 56 21 [2] 59 3b [2] 47 26 [2] 45 27 [2] 5e 21 [2] 42 26 [2] 5e 09 }

  condition:
    any of them
}