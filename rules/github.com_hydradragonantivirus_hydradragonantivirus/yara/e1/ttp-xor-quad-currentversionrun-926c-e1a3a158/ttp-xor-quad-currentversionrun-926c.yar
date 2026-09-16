rule TTP_XOR_QUAD_CurrentVersionRun_926c {
  strings:
    $key_926c = { c1 03 [2] e5 0d [2] ce 21 [2] e0 03 [2] f4 18 [2] fb 02 [2] e5 1f [2] e7 1e [2] fc 18 [2] e0 1f [2] fc 30 }

  condition:
    any of them
}