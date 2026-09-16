rule TTP_XOR_QUAD_CurrentVersionRun_91fa {
  strings:
    $key_91fa = { c2 95 [2] e6 9b [2] cd b7 [2] e3 95 [2] f7 8e [2] f8 94 [2] e6 89 [2] e4 88 [2] ff 8e [2] e3 89 [2] ff a6 }

  condition:
    any of them
}