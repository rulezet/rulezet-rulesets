rule TTP_XOR_QUAD_CurrentVersionRun_02ce {
  strings:
    $key_02ce = { 51 a1 [2] 75 af [2] 5e 83 [2] 70 a1 [2] 64 ba [2] 6b a0 [2] 75 bd [2] 77 bc [2] 6c ba [2] 70 bd [2] 6c 92 }

  condition:
    any of them
}