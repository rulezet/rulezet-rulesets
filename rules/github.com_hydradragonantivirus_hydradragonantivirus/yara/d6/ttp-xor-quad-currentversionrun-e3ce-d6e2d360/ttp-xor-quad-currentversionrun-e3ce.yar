rule TTP_XOR_QUAD_CurrentVersionRun_e3ce {
  strings:
    $key_e3ce = { b0 a1 [2] 94 af [2] bf 83 [2] 91 a1 [2] 85 ba [2] 8a a0 [2] 94 bd [2] 96 bc [2] 8d ba [2] 91 bd [2] 8d 92 }

  condition:
    any of them
}