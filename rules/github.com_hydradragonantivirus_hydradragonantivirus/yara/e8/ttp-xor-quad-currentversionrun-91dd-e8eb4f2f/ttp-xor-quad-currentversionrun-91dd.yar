rule TTP_XOR_QUAD_CurrentVersionRun_91dd {
  strings:
    $key_91dd = { c2 b2 [2] e6 bc [2] cd 90 [2] e3 b2 [2] f7 a9 [2] f8 b3 [2] e6 ae [2] e4 af [2] ff a9 [2] e3 ae [2] ff 81 }

  condition:
    any of them
}