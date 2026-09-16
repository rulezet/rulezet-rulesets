rule TTP_XOR_QUAD_CurrentVersionRun_7ac2 {
  strings:
    $key_7ac2 = { 29 ad [2] 0d a3 [2] 26 8f [2] 08 ad [2] 1c b6 [2] 13 ac [2] 0d b1 [2] 0f b0 [2] 14 b6 [2] 08 b1 [2] 14 9e }

  condition:
    any of them
}