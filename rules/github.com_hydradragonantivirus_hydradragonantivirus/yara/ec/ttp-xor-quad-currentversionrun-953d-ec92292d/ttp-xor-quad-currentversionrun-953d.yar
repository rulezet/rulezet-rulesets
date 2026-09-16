rule TTP_XOR_QUAD_CurrentVersionRun_953d {
  strings:
    $key_953d = { c6 52 [2] e2 5c [2] c9 70 [2] e7 52 [2] f3 49 [2] fc 53 [2] e2 4e [2] e0 4f [2] fb 49 [2] e7 4e [2] fb 61 }

  condition:
    any of them
}