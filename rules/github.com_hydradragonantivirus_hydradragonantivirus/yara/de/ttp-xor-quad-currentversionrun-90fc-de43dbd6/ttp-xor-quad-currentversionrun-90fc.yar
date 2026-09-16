rule TTP_XOR_QUAD_CurrentVersionRun_90fc {
  strings:
    $key_90fc = { c3 93 [2] e7 9d [2] cc b1 [2] e2 93 [2] f6 88 [2] f9 92 [2] e7 8f [2] e5 8e [2] fe 88 [2] e2 8f [2] fe a0 }

  condition:
    any of them
}