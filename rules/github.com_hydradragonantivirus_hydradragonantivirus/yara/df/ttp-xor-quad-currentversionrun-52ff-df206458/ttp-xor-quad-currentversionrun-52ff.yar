rule TTP_XOR_QUAD_CurrentVersionRun_52ff {
  strings:
    $key_52ff = { 01 90 [2] 25 9e [2] 0e b2 [2] 20 90 [2] 34 8b [2] 3b 91 [2] 25 8c [2] 27 8d [2] 3c 8b [2] 20 8c [2] 3c a3 }

  condition:
    any of them
}