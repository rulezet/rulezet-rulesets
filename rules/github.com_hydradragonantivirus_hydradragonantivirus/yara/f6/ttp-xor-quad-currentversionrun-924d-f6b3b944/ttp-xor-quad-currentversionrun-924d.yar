rule TTP_XOR_QUAD_CurrentVersionRun_924d {
  strings:
    $key_924d = { c1 22 [2] e5 2c [2] ce 00 [2] e0 22 [2] f4 39 [2] fb 23 [2] e5 3e [2] e7 3f [2] fc 39 [2] e0 3e [2] fc 11 }

  condition:
    any of them
}