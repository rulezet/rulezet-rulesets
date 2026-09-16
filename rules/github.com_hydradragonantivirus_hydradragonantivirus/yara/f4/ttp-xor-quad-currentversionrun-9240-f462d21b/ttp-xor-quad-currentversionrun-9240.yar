rule TTP_XOR_QUAD_CurrentVersionRun_9240 {
  strings:
    $key_9240 = { c1 2f [2] e5 21 [2] ce 0d [2] e0 2f [2] f4 34 [2] fb 2e [2] e5 33 [2] e7 32 [2] fc 34 [2] e0 33 [2] fc 1c }

  condition:
    any of them
}