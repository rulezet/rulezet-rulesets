rule TTP_XOR_QUAD_CurrentVersionRun_79ff {
  strings:
    $key_79ff = { 2a 90 [2] 0e 9e [2] 25 b2 [2] 0b 90 [2] 1f 8b [2] 10 91 [2] 0e 8c [2] 0c 8d [2] 17 8b [2] 0b 8c [2] 17 a3 }

  condition:
    any of them
}