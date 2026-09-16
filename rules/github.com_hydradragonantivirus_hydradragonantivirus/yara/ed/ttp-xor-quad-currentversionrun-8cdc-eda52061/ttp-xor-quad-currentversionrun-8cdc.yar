rule TTP_XOR_QUAD_CurrentVersionRun_8cdc {
  strings:
    $key_8cdc = { df b3 [2] fb bd [2] d0 91 [2] fe b3 [2] ea a8 [2] e5 b2 [2] fb af [2] f9 ae [2] e2 a8 [2] fe af [2] e2 80 }

  condition:
    any of them
}