rule TTP_XOR_QUAD_CurrentVersionRun_30d2 {
  strings:
    $key_30d2 = { 63 bd [2] 47 b3 [2] 6c 9f [2] 42 bd [2] 56 a6 [2] 59 bc [2] 47 a1 [2] 45 a0 [2] 5e a6 [2] 42 a1 [2] 5e 8e }

  condition:
    any of them
}