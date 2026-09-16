rule TTP_XOR_QUAD_CurrentVersionRun_eac2 {
  strings:
    $key_eac2 = { b9 ad [2] 9d a3 [2] b6 8f [2] 98 ad [2] 8c b6 [2] 83 ac [2] 9d b1 [2] 9f b0 [2] 84 b6 [2] 98 b1 [2] 84 9e }

  condition:
    any of them
}