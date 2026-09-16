rule TTP_XOR_QUAD_CurrentVersionRun_63ff {
  strings:
    $key_63ff = { 30 90 [2] 14 9e [2] 3f b2 [2] 11 90 [2] 05 8b [2] 0a 91 [2] 14 8c [2] 16 8d [2] 0d 8b [2] 11 8c [2] 0d a3 }

  condition:
    any of them
}