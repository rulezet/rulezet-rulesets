rule TTP_XOR_QUAD_CurrentVersionRun_f2ce {
  strings:
    $key_f2ce = { a1 a1 [2] 85 af [2] ae 83 [2] 80 a1 [2] 94 ba [2] 9b a0 [2] 85 bd [2] 87 bc [2] 9c ba [2] 80 bd [2] 9c 92 }

  condition:
    any of them
}