rule TTP_XOR_QUAD_CurrentVersionRun_8cc5 {
  strings:
    $key_8cc5 = { df aa [2] fb a4 [2] d0 88 [2] fe aa [2] ea b1 [2] e5 ab [2] fb b6 [2] f9 b7 [2] e2 b1 [2] fe b6 [2] e2 99 }

  condition:
    any of them
}