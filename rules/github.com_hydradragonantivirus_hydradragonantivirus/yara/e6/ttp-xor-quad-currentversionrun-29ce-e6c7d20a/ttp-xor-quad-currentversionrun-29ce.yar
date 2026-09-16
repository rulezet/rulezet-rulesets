rule TTP_XOR_QUAD_CurrentVersionRun_29ce {
  strings:
    $key_29ce = { 7a a1 [2] 5e af [2] 75 83 [2] 5b a1 [2] 4f ba [2] 40 a0 [2] 5e bd [2] 5c bc [2] 47 ba [2] 5b bd [2] 47 92 }

  condition:
    any of them
}