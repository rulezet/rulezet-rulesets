rule TTP_XOR_QUAD_CurrentVersionRun_bfcf {
  strings:
    $key_bfcf = { ec a0 [2] c8 ae [2] e3 82 [2] cd a0 [2] d9 bb [2] d6 a1 [2] c8 bc [2] ca bd [2] d1 bb [2] cd bc [2] d1 93 }

  condition:
    any of them
}