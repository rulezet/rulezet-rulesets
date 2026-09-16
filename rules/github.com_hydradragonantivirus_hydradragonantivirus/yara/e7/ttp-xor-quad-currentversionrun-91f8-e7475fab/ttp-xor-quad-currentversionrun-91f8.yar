rule TTP_XOR_QUAD_CurrentVersionRun_91f8 {
  strings:
    $key_91f8 = { c2 97 [2] e6 99 [2] cd b5 [2] e3 97 [2] f7 8c [2] f8 96 [2] e6 8b [2] e4 8a [2] ff 8c [2] e3 8b [2] ff a4 }

  condition:
    any of them
}