rule TTP_XOR_QUAD_CurrentVersionRun_70cf {
  strings:
    $key_70cf = { 23 a0 [2] 07 ae [2] 2c 82 [2] 02 a0 [2] 16 bb [2] 19 a1 [2] 07 bc [2] 05 bd [2] 1e bb [2] 02 bc [2] 1e 93 }

  condition:
    any of them
}