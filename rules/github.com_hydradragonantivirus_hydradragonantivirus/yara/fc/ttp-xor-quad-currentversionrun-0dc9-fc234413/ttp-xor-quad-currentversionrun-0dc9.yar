rule TTP_XOR_QUAD_CurrentVersionRun_0dc9 {
  strings:
    $key_0dc9 = { 5e a6 [2] 7a a8 [2] 51 84 [2] 7f a6 [2] 6b bd [2] 64 a7 [2] 7a ba [2] 78 bb [2] 63 bd [2] 7f ba [2] 63 95 }

  condition:
    any of them
}