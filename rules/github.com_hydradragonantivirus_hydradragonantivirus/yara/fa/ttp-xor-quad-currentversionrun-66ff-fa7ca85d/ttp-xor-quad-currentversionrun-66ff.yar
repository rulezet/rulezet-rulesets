rule TTP_XOR_QUAD_CurrentVersionRun_66ff {
  strings:
    $key_66ff = { 35 90 [2] 11 9e [2] 3a b2 [2] 14 90 [2] 00 8b [2] 0f 91 [2] 11 8c [2] 13 8d [2] 08 8b [2] 14 8c [2] 08 a3 }

  condition:
    any of them
}