rule TTP_XOR_QUAD_CurrentVersionRun_04ff {
  strings:
    $key_04ff = { 57 90 [2] 73 9e [2] 58 b2 [2] 76 90 [2] 62 8b [2] 6d 91 [2] 73 8c [2] 71 8d [2] 6a 8b [2] 76 8c [2] 6a a3 }

  condition:
    any of them
}