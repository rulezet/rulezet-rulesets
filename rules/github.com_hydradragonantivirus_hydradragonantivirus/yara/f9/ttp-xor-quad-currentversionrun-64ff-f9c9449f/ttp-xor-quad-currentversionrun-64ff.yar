rule TTP_XOR_QUAD_CurrentVersionRun_64ff {
  strings:
    $key_64ff = { 37 90 [2] 13 9e [2] 38 b2 [2] 16 90 [2] 02 8b [2] 0d 91 [2] 13 8c [2] 11 8d [2] 0a 8b [2] 16 8c [2] 0a a3 }

  condition:
    any of them
}