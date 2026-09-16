rule TTP_XOR_QUAD_CurrentVersionRun_917a {
  strings:
    $key_917a = { c2 15 [2] e6 1b [2] cd 37 [2] e3 15 [2] f7 0e [2] f8 14 [2] e6 09 [2] e4 08 [2] ff 0e [2] e3 09 [2] ff 26 }

  condition:
    any of them
}