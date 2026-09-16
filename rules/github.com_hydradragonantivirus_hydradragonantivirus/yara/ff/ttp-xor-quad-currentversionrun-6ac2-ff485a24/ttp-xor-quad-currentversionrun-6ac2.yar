rule TTP_XOR_QUAD_CurrentVersionRun_6ac2 {
  strings:
    $key_6ac2 = { 39 ad [2] 1d a3 [2] 36 8f [2] 18 ad [2] 0c b6 [2] 03 ac [2] 1d b1 [2] 1f b0 [2] 04 b6 [2] 18 b1 [2] 04 9e }

  condition:
    any of them
}