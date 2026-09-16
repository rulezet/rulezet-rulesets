rule TTP_XOR_QUAD_CurrentVersionRun_95eb {
  strings:
    $key_95eb = { c6 84 [2] e2 8a [2] c9 a6 [2] e7 84 [2] f3 9f [2] fc 85 [2] e2 98 [2] e0 99 [2] fb 9f [2] e7 98 [2] fb b7 }

  condition:
    any of them
}