rule TTP_XOR_QUAD_CurrentVersionRun_9172 {
  strings:
    $key_9172 = { c2 1d [2] e6 13 [2] cd 3f [2] e3 1d [2] f7 06 [2] f8 1c [2] e6 01 [2] e4 00 [2] ff 06 [2] e3 01 [2] ff 2e }

  condition:
    any of them
}