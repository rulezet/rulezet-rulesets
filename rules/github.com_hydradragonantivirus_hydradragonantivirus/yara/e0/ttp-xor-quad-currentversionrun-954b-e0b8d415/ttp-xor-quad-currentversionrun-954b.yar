rule TTP_XOR_QUAD_CurrentVersionRun_954b {
  strings:
    $key_954b = { c6 24 [2] e2 2a [2] c9 06 [2] e7 24 [2] f3 3f [2] fc 25 [2] e2 38 [2] e0 39 [2] fb 3f [2] e7 38 [2] fb 17 }

  condition:
    any of them
}