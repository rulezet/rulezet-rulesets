rule TTP_XOR_QUAD_CurrentVersionRun_95ab {
  strings:
    $key_95ab = { c6 c4 [2] e2 ca [2] c9 e6 [2] e7 c4 [2] f3 df [2] fc c5 [2] e2 d8 [2] e0 d9 [2] fb df [2] e7 d8 [2] fb f7 }

  condition:
    any of them
}