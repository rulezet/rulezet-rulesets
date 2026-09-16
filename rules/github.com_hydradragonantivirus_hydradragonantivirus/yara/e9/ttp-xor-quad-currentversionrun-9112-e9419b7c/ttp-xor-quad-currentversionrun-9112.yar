rule TTP_XOR_QUAD_CurrentVersionRun_9112 {
  strings:
    $key_9112 = { c2 7d [2] e6 73 [2] cd 5f [2] e3 7d [2] f7 66 [2] f8 7c [2] e6 61 [2] e4 60 [2] ff 66 [2] e3 61 [2] ff 4e }

  condition:
    any of them
}