rule TTP_XOR_QUAD_CurrentVersionRun_2927 {
  strings:
    $key_2927 = { 7a 48 [2] 5e 46 [2] 75 6a [2] 5b 48 [2] 4f 53 [2] 40 49 [2] 5e 54 [2] 5c 55 [2] 47 53 [2] 5b 54 [2] 47 7b }

  condition:
    any of them
}