rule TTP_XOR_QUAD_CurrentVersionRun_92fc {
  strings:
    $key_92fc = { c1 93 [2] e5 9d [2] ce b1 [2] e0 93 [2] f4 88 [2] fb 92 [2] e5 8f [2] e7 8e [2] fc 88 [2] e0 8f [2] fc a0 }

  condition:
    any of them
}