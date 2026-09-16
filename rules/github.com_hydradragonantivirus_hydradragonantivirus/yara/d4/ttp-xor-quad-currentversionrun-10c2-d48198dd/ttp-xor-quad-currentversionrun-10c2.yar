rule TTP_XOR_QUAD_CurrentVersionRun_10c2 {
  strings:
    $key_10c2 = { 43 ad [2] 67 a3 [2] 4c 8f [2] 62 ad [2] 76 b6 [2] 79 ac [2] 67 b1 [2] 65 b0 [2] 7e b6 [2] 62 b1 [2] 7e 9e }

  condition:
    any of them
}