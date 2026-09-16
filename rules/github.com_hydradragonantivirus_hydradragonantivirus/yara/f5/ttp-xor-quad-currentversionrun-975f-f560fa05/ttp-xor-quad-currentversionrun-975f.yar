rule TTP_XOR_QUAD_CurrentVersionRun_975f {
  strings:
    $key_975f = { c4 30 [2] e0 3e [2] cb 12 [2] e5 30 [2] f1 2b [2] fe 31 [2] e0 2c [2] e2 2d [2] f9 2b [2] e5 2c [2] f9 03 }

  condition:
    any of them
}