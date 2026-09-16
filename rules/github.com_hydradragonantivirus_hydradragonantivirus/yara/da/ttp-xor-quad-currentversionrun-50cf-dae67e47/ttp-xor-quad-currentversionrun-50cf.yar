rule TTP_XOR_QUAD_CurrentVersionRun_50cf {
  strings:
    $key_50cf = { 03 a0 [2] 27 ae [2] 0c 82 [2] 22 a0 [2] 36 bb [2] 39 a1 [2] 27 bc [2] 25 bd [2] 3e bb [2] 22 bc [2] 3e 93 }

  condition:
    any of them
}