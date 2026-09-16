rule TTP_XOR_QUAD_CurrentVersionRun_29d2 {
  strings:
    $key_29d2 = { 7a bd [2] 5e b3 [2] 75 9f [2] 5b bd [2] 4f a6 [2] 40 bc [2] 5e a1 [2] 5c a0 [2] 47 a6 [2] 5b a1 [2] 47 8e }

  condition:
    any of them
}