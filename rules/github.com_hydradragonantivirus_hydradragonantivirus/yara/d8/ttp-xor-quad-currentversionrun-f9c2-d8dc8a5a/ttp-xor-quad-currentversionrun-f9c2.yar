rule TTP_XOR_QUAD_CurrentVersionRun_f9c2 {
  strings:
    $key_f9c2 = { aa ad [2] 8e a3 [2] a5 8f [2] 8b ad [2] 9f b6 [2] 90 ac [2] 8e b1 [2] 8c b0 [2] 97 b6 [2] 8b b1 [2] 97 9e }

  condition:
    any of them
}