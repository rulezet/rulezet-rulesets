rule TTP_XOR_QUAD_CurrentVersionRun_4ece {
  strings:
    $key_4ece = { 1d a1 [2] 39 af [2] 12 83 [2] 3c a1 [2] 28 ba [2] 27 a0 [2] 39 bd [2] 3b bc [2] 20 ba [2] 3c bd [2] 20 92 }

  condition:
    any of them
}