rule TTP_XOR_QUAD_CurrentVersionRun_2cd0 {
  strings:
    $key_2cd0 = { 7f bf [2] 5b b1 [2] 70 9d [2] 5e bf [2] 4a a4 [2] 45 be [2] 5b a3 [2] 59 a2 [2] 42 a4 [2] 5e a3 [2] 42 8c }

  condition:
    any of them
}