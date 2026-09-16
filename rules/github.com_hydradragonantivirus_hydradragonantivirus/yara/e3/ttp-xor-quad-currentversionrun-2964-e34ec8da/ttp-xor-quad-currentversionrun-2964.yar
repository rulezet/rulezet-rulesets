rule TTP_XOR_QUAD_CurrentVersionRun_2964 {
  strings:
    $key_2964 = { 7a 0b [2] 5e 05 [2] 75 29 [2] 5b 0b [2] 4f 10 [2] 40 0a [2] 5e 17 [2] 5c 16 [2] 47 10 [2] 5b 17 [2] 47 38 }

  condition:
    any of them
}