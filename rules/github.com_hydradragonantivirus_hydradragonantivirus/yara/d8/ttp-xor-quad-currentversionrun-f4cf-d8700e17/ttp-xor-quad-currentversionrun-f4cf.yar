rule TTP_XOR_QUAD_CurrentVersionRun_f4cf {
  strings:
    $key_f4cf = { a7 a0 [2] 83 ae [2] a8 82 [2] 86 a0 [2] 92 bb [2] 9d a1 [2] 83 bc [2] 81 bd [2] 9a bb [2] 86 bc [2] 9a 93 }

  condition:
    any of them
}