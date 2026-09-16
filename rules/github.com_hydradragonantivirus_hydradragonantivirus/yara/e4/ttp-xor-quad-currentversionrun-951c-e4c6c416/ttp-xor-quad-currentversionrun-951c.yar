rule TTP_XOR_QUAD_CurrentVersionRun_951c {
  strings:
    $key_951c = { c6 73 [2] e2 7d [2] c9 51 [2] e7 73 [2] f3 68 [2] fc 72 [2] e2 6f [2] e0 6e [2] fb 68 [2] e7 6f [2] fb 40 }

  condition:
    any of them
}