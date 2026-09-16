rule TTP_XOR_QUAD_CurrentVersionRun_38c2 {
  strings:
    $key_38c2 = { 6b ad [2] 4f a3 [2] 64 8f [2] 4a ad [2] 5e b6 [2] 51 ac [2] 4f b1 [2] 4d b0 [2] 56 b6 [2] 4a b1 [2] 56 9e }

  condition:
    any of them
}