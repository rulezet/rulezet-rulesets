rule TTP_XOR_QUAD_CurrentVersionRun_34cf {
  strings:
    $key_34cf = { 67 a0 [2] 43 ae [2] 68 82 [2] 46 a0 [2] 52 bb [2] 5d a1 [2] 43 bc [2] 41 bd [2] 5a bb [2] 46 bc [2] 5a 93 }

  condition:
    any of them
}