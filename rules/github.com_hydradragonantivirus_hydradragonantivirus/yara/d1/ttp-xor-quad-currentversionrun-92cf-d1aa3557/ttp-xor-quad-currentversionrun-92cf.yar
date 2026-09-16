rule TTP_XOR_QUAD_CurrentVersionRun_92cf {
  strings:
    $key_92cf = { c1 a0 [2] e5 ae [2] ce 82 [2] e0 a0 [2] f4 bb [2] fb a1 [2] e5 bc [2] e7 bd [2] fc bb [2] e0 bc [2] fc 93 }

  condition:
    any of them
}