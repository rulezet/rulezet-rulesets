rule TTP_XOR_QUAD_CurrentVersionRun_53d2 {
  strings:
    $key_53d2 = { 00 bd [2] 24 b3 [2] 0f 9f [2] 21 bd [2] 35 a6 [2] 3a bc [2] 24 a1 [2] 26 a0 [2] 3d a6 [2] 21 a1 [2] 3d 8e }

  condition:
    any of them
}