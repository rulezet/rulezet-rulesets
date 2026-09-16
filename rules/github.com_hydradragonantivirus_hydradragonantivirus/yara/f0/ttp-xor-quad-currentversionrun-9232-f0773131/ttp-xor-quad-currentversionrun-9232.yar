rule TTP_XOR_QUAD_CurrentVersionRun_9232 {
  strings:
    $key_9232 = { c1 5d [2] e5 53 [2] ce 7f [2] e0 5d [2] f4 46 [2] fb 5c [2] e5 41 [2] e7 40 [2] fc 46 [2] e0 41 [2] fc 6e }

  condition:
    any of them
}