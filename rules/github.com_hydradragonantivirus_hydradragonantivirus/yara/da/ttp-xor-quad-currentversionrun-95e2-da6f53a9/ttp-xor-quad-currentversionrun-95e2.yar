rule TTP_XOR_QUAD_CurrentVersionRun_95e2 {
  strings:
    $key_95e2 = { c6 8d [2] e2 83 [2] c9 af [2] e7 8d [2] f3 96 [2] fc 8c [2] e2 91 [2] e0 90 [2] fb 96 [2] e7 91 [2] fb be }

  condition:
    any of them
}