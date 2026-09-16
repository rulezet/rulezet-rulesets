rule TTP_XOR_QUAD_CurrentVersionRun_09d5 {
  strings:
    $key_09d5 = { 5a ba [2] 7e b4 [2] 55 98 [2] 7b ba [2] 6f a1 [2] 60 bb [2] 7e a6 [2] 7c a7 [2] 67 a1 [2] 7b a6 [2] 67 89 }

  condition:
    any of them
}