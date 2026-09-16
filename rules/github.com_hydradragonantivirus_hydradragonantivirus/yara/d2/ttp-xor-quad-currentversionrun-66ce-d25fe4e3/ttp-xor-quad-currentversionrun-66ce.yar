rule TTP_XOR_QUAD_CurrentVersionRun_66ce {
  strings:
    $key_66ce = { 35 a1 [2] 11 af [2] 3a 83 [2] 14 a1 [2] 00 ba [2] 0f a0 [2] 11 bd [2] 13 bc [2] 08 ba [2] 14 bd [2] 08 92 }

  condition:
    any of them
}