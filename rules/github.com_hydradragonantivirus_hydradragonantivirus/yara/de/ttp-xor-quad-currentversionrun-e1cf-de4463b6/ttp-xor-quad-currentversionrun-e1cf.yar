rule TTP_XOR_QUAD_CurrentVersionRun_e1cf {
  strings:
    $key_e1cf = { b2 a0 [2] 96 ae [2] bd 82 [2] 93 a0 [2] 87 bb [2] 88 a1 [2] 96 bc [2] 94 bd [2] 8f bb [2] 93 bc [2] 8f 93 }

  condition:
    any of them
}