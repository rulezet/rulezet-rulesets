rule TTP_XOR_QUAD_CurrentVersionRun_9222 {
  strings:
    $key_9222 = { c1 4d [2] e5 43 [2] ce 6f [2] e0 4d [2] f4 56 [2] fb 4c [2] e5 51 [2] e7 50 [2] fc 56 [2] e0 51 [2] fc 7e }

  condition:
    any of them
}