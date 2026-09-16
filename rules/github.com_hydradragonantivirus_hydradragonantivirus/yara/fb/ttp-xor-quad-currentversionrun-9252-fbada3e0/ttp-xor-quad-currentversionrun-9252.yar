rule TTP_XOR_QUAD_CurrentVersionRun_9252 {
  strings:
    $key_9252 = { c1 3d [2] e5 33 [2] ce 1f [2] e0 3d [2] f4 26 [2] fb 3c [2] e5 21 [2] e7 20 [2] fc 26 [2] e0 21 [2] fc 0e }

  condition:
    any of them
}