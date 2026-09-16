rule TTP_XOR_QUAD_CurrentVersionRun_f9d2 {
  strings:
    $key_f9d2 = { aa bd [2] 8e b3 [2] a5 9f [2] 8b bd [2] 9f a6 [2] 90 bc [2] 8e a1 [2] 8c a0 [2] 97 a6 [2] 8b a1 [2] 97 8e }

  condition:
    any of them
}