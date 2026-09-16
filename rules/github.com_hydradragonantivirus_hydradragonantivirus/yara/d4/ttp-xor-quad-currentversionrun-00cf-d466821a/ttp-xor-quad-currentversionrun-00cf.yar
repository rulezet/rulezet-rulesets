rule TTP_XOR_QUAD_CurrentVersionRun_00cf {
  strings:
    $key_00cf = { 53 a0 [2] 77 ae [2] 5c 82 [2] 72 a0 [2] 66 bb [2] 69 a1 [2] 77 bc [2] 75 bd [2] 6e bb [2] 72 bc [2] 6e 93 }

  condition:
    any of them
}