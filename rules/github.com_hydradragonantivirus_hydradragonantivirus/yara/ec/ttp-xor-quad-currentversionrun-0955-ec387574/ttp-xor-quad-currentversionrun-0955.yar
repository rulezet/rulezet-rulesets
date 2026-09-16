rule TTP_XOR_QUAD_CurrentVersionRun_0955 {
  strings:
    $key_0955 = { 5a 3a [2] 7e 34 [2] 55 18 [2] 7b 3a [2] 6f 21 [2] 60 3b [2] 7e 26 [2] 7c 27 [2] 67 21 [2] 7b 26 [2] 67 09 }

  condition:
    any of them
}