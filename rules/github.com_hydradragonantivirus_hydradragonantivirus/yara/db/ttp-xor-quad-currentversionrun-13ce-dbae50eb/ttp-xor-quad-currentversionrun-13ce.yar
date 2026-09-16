rule TTP_XOR_QUAD_CurrentVersionRun_13ce {
  strings:
    $key_13ce = { 40 a1 [2] 64 af [2] 4f 83 [2] 61 a1 [2] 75 ba [2] 7a a0 [2] 64 bd [2] 66 bc [2] 7d ba [2] 61 bd [2] 7d 92 }

  condition:
    any of them
}