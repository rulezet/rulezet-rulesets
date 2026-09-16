rule TTP_XOR_QUAD_CurrentVersionRun_9117 {
  strings:
    $key_9117 = { c2 78 [2] e6 76 [2] cd 5a [2] e3 78 [2] f7 63 [2] f8 79 [2] e6 64 [2] e4 65 [2] ff 63 [2] e3 64 [2] ff 4b }

  condition:
    any of them
}