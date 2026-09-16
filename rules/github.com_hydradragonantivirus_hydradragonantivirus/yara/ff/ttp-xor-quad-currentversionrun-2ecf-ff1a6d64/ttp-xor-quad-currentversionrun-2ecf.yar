rule TTP_XOR_QUAD_CurrentVersionRun_2ecf {
  strings:
    $key_2ecf = { 7d a0 [2] 59 ae [2] 72 82 [2] 5c a0 [2] 48 bb [2] 47 a1 [2] 59 bc [2] 5b bd [2] 40 bb [2] 5c bc [2] 40 93 }

  condition:
    any of them
}