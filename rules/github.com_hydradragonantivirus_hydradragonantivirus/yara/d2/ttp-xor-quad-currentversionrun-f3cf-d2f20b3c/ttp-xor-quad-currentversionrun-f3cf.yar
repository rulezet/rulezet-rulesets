rule TTP_XOR_QUAD_CurrentVersionRun_f3cf {
  strings:
    $key_f3cf = { a0 a0 [2] 84 ae [2] af 82 [2] 81 a0 [2] 95 bb [2] 9a a1 [2] 84 bc [2] 86 bd [2] 9d bb [2] 81 bc [2] 9d 93 }

  condition:
    any of them
}