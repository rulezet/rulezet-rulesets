rule TTP_XOR_QUAD_CurrentVersionRun_910c {
  strings:
    $key_910c = { c2 63 [2] e6 6d [2] cd 41 [2] e3 63 [2] f7 78 [2] f8 62 [2] e6 7f [2] e4 7e [2] ff 78 [2] e3 7f [2] ff 50 }

  condition:
    any of them
}