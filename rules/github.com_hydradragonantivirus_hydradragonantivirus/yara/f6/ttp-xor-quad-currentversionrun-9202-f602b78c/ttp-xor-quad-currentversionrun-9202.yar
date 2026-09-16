rule TTP_XOR_QUAD_CurrentVersionRun_9202 {
  strings:
    $key_9202 = { c1 6d [2] e5 63 [2] ce 4f [2] e0 6d [2] f4 76 [2] fb 6c [2] e5 71 [2] e7 70 [2] fc 76 [2] e0 71 [2] fc 5e }

  condition:
    any of them
}