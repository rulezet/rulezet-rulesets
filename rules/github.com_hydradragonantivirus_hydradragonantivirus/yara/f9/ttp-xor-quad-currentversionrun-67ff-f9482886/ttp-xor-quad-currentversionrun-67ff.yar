rule TTP_XOR_QUAD_CurrentVersionRun_67ff {
  strings:
    $key_67ff = { 34 90 [2] 10 9e [2] 3b b2 [2] 15 90 [2] 01 8b [2] 0e 91 [2] 10 8c [2] 12 8d [2] 09 8b [2] 15 8c [2] 09 a3 }

  condition:
    any of them
}