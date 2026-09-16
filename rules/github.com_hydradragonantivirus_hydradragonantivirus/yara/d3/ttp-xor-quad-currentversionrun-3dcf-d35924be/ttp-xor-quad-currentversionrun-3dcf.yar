rule TTP_XOR_QUAD_CurrentVersionRun_3dcf {
  strings:
    $key_3dcf = { 6e a0 [2] 4a ae [2] 61 82 [2] 4f a0 [2] 5b bb [2] 54 a1 [2] 4a bc [2] 48 bd [2] 53 bb [2] 4f bc [2] 53 93 }

  condition:
    any of them
}