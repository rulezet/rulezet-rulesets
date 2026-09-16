rule TTP_XOR_QUAD_CurrentVersionRun_926b {
  strings:
    $key_926b = { c1 04 [2] e5 0a [2] ce 26 [2] e0 04 [2] f4 1f [2] fb 05 [2] e5 18 [2] e7 19 [2] fc 1f [2] e0 18 [2] fc 37 }

  condition:
    any of them
}