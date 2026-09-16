rule TTP_XOR_QUAD_CurrentVersionRun_91ff {
  strings:
    $key_91ff = { c2 90 [2] e6 9e [2] cd b2 [2] e3 90 [2] f7 8b [2] f8 91 [2] e6 8c [2] e4 8d [2] ff 8b [2] e3 8c [2] ff a3 }

  condition:
    any of them
}