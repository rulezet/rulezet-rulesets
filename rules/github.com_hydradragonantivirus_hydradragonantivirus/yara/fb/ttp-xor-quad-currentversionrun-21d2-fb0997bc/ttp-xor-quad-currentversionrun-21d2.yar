rule TTP_XOR_QUAD_CurrentVersionRun_21d2 {
  strings:
    $key_21d2 = { 72 bd [2] 56 b3 [2] 7d 9f [2] 53 bd [2] 47 a6 [2] 48 bc [2] 56 a1 [2] 54 a0 [2] 4f a6 [2] 53 a1 [2] 4f 8e }

  condition:
    any of them
}