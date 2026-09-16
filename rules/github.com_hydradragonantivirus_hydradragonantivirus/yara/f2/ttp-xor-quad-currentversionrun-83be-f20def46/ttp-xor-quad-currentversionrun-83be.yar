rule TTP_XOR_QUAD_CurrentVersionRun_83be {
  strings:
    $key_83be = { d0 d1 [2] f4 df [2] df f3 [2] f1 d1 [2] e5 ca [2] ea d0 [2] f4 cd [2] f6 cc [2] ed ca [2] f1 cd [2] ed e2 }

  condition:
    any of them
}