rule TTP_XOR_QUAD_CurrentVersionRun_59c8 {
  strings:
    $key_59c8 = { 0a a7 [2] 2e a9 [2] 05 85 [2] 2b a7 [2] 3f bc [2] 30 a6 [2] 2e bb [2] 2c ba [2] 37 bc [2] 2b bb [2] 37 94 }

  condition:
    any of them
}