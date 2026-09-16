rule TTP_XOR_QUAD_CurrentVersionRun_fdd2 {
  strings:
    $key_fdd2 = { ae bd [2] 8a b3 [2] a1 9f [2] 8f bd [2] 9b a6 [2] 94 bc [2] 8a a1 [2] 88 a0 [2] 93 a6 [2] 8f a1 [2] 93 8e }

  condition:
    any of them
}