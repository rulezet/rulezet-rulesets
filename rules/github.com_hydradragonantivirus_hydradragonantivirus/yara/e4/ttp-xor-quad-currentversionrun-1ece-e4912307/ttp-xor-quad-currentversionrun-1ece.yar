rule TTP_XOR_QUAD_CurrentVersionRun_1ece {
  strings:
    $key_1ece = { 4d a1 [2] 69 af [2] 42 83 [2] 6c a1 [2] 78 ba [2] 77 a0 [2] 69 bd [2] 6b bc [2] 70 ba [2] 6c bd [2] 70 92 }

  condition:
    any of them
}