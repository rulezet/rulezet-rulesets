rule TTP_XOR_QUAD_CurrentVersionRun_9132 {
  strings:
    $key_9132 = { c2 5d [2] e6 53 [2] cd 7f [2] e3 5d [2] f7 46 [2] f8 5c [2] e6 41 [2] e4 40 [2] ff 46 [2] e3 41 [2] ff 6e }

  condition:
    any of them
}