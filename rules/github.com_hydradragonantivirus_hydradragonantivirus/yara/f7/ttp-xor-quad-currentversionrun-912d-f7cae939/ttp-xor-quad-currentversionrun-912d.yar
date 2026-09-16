rule TTP_XOR_QUAD_CurrentVersionRun_912d {
  strings:
    $key_912d = { c2 42 [2] e6 4c [2] cd 60 [2] e3 42 [2] f7 59 [2] f8 43 [2] e6 5e [2] e4 5f [2] ff 59 [2] e3 5e [2] ff 71 }

  condition:
    any of them
}