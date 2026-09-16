rule TTP_XOR_QUAD_CurrentVersionRun_f1cf {
  strings:
    $key_f1cf = { a2 a0 [2] 86 ae [2] ad 82 [2] 83 a0 [2] 97 bb [2] 98 a1 [2] 86 bc [2] 84 bd [2] 9f bb [2] 83 bc [2] 9f 93 }

  condition:
    any of them
}