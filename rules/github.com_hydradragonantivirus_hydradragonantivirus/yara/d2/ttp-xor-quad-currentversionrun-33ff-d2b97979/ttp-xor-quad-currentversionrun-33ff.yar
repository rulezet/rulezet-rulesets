rule TTP_XOR_QUAD_CurrentVersionRun_33ff {
  strings:
    $key_33ff = { 60 90 [2] 44 9e [2] 6f b2 [2] 41 90 [2] 55 8b [2] 5a 91 [2] 44 8c [2] 46 8d [2] 5d 8b [2] 41 8c [2] 5d a3 }

  condition:
    any of them
}