rule TTP_XOR_QUAD_CurrentVersionRun_e4ce {
  strings:
    $key_e4ce = { b7 a1 [2] 93 af [2] b8 83 [2] 96 a1 [2] 82 ba [2] 8d a0 [2] 93 bd [2] 91 bc [2] 8a ba [2] 96 bd [2] 8a 92 }

  condition:
    any of them
}