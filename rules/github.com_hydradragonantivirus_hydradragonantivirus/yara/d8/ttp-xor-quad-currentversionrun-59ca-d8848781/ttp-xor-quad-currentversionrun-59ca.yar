rule TTP_XOR_QUAD_CurrentVersionRun_59ca {
  strings:
    $key_59ca = { 0a a5 [2] 2e ab [2] 05 87 [2] 2b a5 [2] 3f be [2] 30 a4 [2] 2e b9 [2] 2c b8 [2] 37 be [2] 2b b9 [2] 37 96 }

  condition:
    any of them
}