rule TTP_XOR_QUAD_CurrentVersionRun_953e {
  strings:
    $key_953e = { c6 51 [2] e2 5f [2] c9 73 [2] e7 51 [2] f3 4a [2] fc 50 [2] e2 4d [2] e0 4c [2] fb 4a [2] e7 4d [2] fb 62 }

  condition:
    any of them
}