rule TTP_XOR_QUAD_CurrentVersionRun_fdc2 {
  strings:
    $key_fdc2 = { ae ad [2] 8a a3 [2] a1 8f [2] 8f ad [2] 9b b6 [2] 94 ac [2] 8a b1 [2] 88 b0 [2] 93 b6 [2] 8f b1 [2] 93 9e }

  condition:
    any of them
}