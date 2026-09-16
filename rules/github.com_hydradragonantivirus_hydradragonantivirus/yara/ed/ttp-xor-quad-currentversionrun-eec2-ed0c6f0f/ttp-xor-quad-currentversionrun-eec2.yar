rule TTP_XOR_QUAD_CurrentVersionRun_eec2 {
  strings:
    $key_eec2 = { bd ad [2] 99 a3 [2] b2 8f [2] 9c ad [2] 88 b6 [2] 87 ac [2] 99 b1 [2] 9b b0 [2] 80 b6 [2] 9c b1 [2] 80 9e }

  condition:
    any of them
}