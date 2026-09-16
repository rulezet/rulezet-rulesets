rule TTP_XOR_QUAD_CurrentVersionRun_925d {
  strings:
    $key_925d = { c1 32 [2] e5 3c [2] ce 10 [2] e0 32 [2] f4 29 [2] fb 33 [2] e5 2e [2] e7 2f [2] fc 29 [2] e0 2e [2] fc 01 }

  condition:
    any of them
}