rule TTP_XOR_QUAD_CurrentVersionRun_21cf {
  strings:
    $key_21cf = { 72 a0 [2] 56 ae [2] 7d 82 [2] 53 a0 [2] 47 bb [2] 48 a1 [2] 56 bc [2] 54 bd [2] 4f bb [2] 53 bc [2] 4f 93 }

  condition:
    any of them
}