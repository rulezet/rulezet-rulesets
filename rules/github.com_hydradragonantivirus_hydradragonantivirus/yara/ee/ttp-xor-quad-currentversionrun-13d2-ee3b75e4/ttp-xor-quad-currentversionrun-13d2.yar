rule TTP_XOR_QUAD_CurrentVersionRun_13d2 {
  strings:
    $key_13d2 = { 40 bd [2] 64 b3 [2] 4f 9f [2] 61 bd [2] 75 a6 [2] 7a bc [2] 64 a1 [2] 66 a0 [2] 7d a6 [2] 61 a1 [2] 7d 8e }

  condition:
    any of them
}