rule TTP_XOR_QUAD_CurrentVersionRun_87ce {
  strings:
    $key_87ce = { d4 a1 [2] f0 af [2] db 83 [2] f5 a1 [2] e1 ba [2] ee a0 [2] f0 bd [2] f2 bc [2] e9 ba [2] f5 bd [2] e9 92 }

  condition:
    any of them
}