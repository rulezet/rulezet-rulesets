rule TTP_XOR_QUAD_CurrentVersionRun_98ce {
  strings:
    $key_98ce = { cb a1 [2] ef af [2] c4 83 [2] ea a1 [2] fe ba [2] f1 a0 [2] ef bd [2] ed bc [2] f6 ba [2] ea bd [2] f6 92 }

  condition:
    any of them
}