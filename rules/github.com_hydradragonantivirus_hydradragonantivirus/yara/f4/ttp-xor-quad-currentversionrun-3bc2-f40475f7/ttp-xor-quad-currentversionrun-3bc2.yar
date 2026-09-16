rule TTP_XOR_QUAD_CurrentVersionRun_3bc2 {
  strings:
    $key_3bc2 = { 68 ad [2] 4c a3 [2] 67 8f [2] 49 ad [2] 5d b6 [2] 52 ac [2] 4c b1 [2] 4e b0 [2] 55 b6 [2] 49 b1 [2] 55 9e }

  condition:
    any of them
}