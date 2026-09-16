rule TTP_XOR_QUAD_CurrentVersionRun_2946 {
  strings:
    $key_2946 = { 7a 29 [2] 5e 27 [2] 75 0b [2] 5b 29 [2] 4f 32 [2] 40 28 [2] 5e 35 [2] 5c 34 [2] 47 32 [2] 5b 35 [2] 47 1a }

  condition:
    any of them
}