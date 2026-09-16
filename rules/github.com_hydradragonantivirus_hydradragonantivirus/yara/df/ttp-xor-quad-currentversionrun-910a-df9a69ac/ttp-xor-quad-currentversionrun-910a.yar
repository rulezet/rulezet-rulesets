rule TTP_XOR_QUAD_CurrentVersionRun_910a {
  strings:
    $key_910a = { c2 65 [2] e6 6b [2] cd 47 [2] e3 65 [2] f7 7e [2] f8 64 [2] e6 79 [2] e4 78 [2] ff 7e [2] e3 79 [2] ff 56 }

  condition:
    any of them
}