rule TTP_XOR_QUAD_CurrentVersionRun_49ce {
  strings:
    $key_49ce = { 1a a1 [2] 3e af [2] 15 83 [2] 3b a1 [2] 2f ba [2] 20 a0 [2] 3e bd [2] 3c bc [2] 27 ba [2] 3b bd [2] 27 92 }

  condition:
    any of them
}