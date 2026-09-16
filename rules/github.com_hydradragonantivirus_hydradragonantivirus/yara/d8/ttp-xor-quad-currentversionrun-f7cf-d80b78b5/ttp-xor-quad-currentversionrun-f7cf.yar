rule TTP_XOR_QUAD_CurrentVersionRun_f7cf {
  strings:
    $key_f7cf = { a4 a0 [2] 80 ae [2] ab 82 [2] 85 a0 [2] 91 bb [2] 9e a1 [2] 80 bc [2] 82 bd [2] 99 bb [2] 85 bc [2] 99 93 }

  condition:
    any of them
}