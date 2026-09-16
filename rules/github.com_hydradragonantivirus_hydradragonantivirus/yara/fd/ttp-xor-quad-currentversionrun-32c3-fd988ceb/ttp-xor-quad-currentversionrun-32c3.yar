rule TTP_XOR_QUAD_CurrentVersionRun_32c3 {
  strings:
    $key_32c3 = { 61 ac [2] 45 a2 [2] 6e 8e [2] 40 ac [2] 54 b7 [2] 5b ad [2] 45 b0 [2] 47 b1 [2] 5c b7 [2] 40 b0 [2] 5c 9f }

  condition:
    any of them
}