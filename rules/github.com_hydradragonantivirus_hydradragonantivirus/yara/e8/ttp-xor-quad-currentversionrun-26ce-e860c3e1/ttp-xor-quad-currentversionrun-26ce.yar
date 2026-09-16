rule TTP_XOR_QUAD_CurrentVersionRun_26ce {
  strings:
    $key_26ce = { 75 a1 [2] 51 af [2] 7a 83 [2] 54 a1 [2] 40 ba [2] 4f a0 [2] 51 bd [2] 53 bc [2] 48 ba [2] 54 bd [2] 48 92 }

  condition:
    any of them
}