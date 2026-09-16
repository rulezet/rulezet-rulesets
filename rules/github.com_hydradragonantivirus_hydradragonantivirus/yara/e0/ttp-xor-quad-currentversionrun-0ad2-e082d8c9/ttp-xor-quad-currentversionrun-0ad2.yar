rule TTP_XOR_QUAD_CurrentVersionRun_0ad2 {
  strings:
    $key_0ad2 = { 59 bd [2] 7d b3 [2] 56 9f [2] 78 bd [2] 6c a6 [2] 63 bc [2] 7d a1 [2] 7f a0 [2] 64 a6 [2] 78 a1 [2] 64 8e }

  condition:
    any of them
}