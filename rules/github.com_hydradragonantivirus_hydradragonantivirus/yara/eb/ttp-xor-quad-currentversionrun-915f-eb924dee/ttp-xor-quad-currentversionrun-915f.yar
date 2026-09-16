rule TTP_XOR_QUAD_CurrentVersionRun_915f {
  strings:
    $key_915f = { c2 30 [2] e6 3e [2] cd 12 [2] e3 30 [2] f7 2b [2] f8 31 [2] e6 2c [2] e4 2d [2] ff 2b [2] e3 2c [2] ff 03 }

  condition:
    any of them
}