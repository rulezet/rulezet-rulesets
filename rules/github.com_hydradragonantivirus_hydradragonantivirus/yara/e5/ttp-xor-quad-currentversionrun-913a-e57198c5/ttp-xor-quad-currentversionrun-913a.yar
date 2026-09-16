rule TTP_XOR_QUAD_CurrentVersionRun_913a {
  strings:
    $key_913a = { c2 55 [2] e6 5b [2] cd 77 [2] e3 55 [2] f7 4e [2] f8 54 [2] e6 49 [2] e4 48 [2] ff 4e [2] e3 49 [2] ff 66 }

  condition:
    any of them
}