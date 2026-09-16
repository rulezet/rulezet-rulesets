rule TTP_XOR_QUAD_CurrentVersionRun_2945 {
  strings:
    $key_2945 = { 7a 2a [2] 5e 24 [2] 75 08 [2] 5b 2a [2] 4f 31 [2] 40 2b [2] 5e 36 [2] 5c 37 [2] 47 31 [2] 5b 36 [2] 47 19 }

  condition:
    any of them
}