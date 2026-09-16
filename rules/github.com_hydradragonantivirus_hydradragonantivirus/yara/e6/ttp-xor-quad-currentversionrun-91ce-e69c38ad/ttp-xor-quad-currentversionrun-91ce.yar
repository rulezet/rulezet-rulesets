rule TTP_XOR_QUAD_CurrentVersionRun_91ce {
  strings:
    $key_91ce = { c2 a1 [2] e6 af [2] cd 83 [2] e3 a1 [2] f7 ba [2] f8 a0 [2] e6 bd [2] e4 bc [2] ff ba [2] e3 bd [2] ff 92 }

  condition:
    any of them
}