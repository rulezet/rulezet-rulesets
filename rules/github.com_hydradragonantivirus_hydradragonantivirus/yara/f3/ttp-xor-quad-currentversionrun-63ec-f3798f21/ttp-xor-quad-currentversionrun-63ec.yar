rule TTP_XOR_QUAD_CurrentVersionRun_63ec {
  strings:
    $key_63ec = { 30 83 [2] 14 8d [2] 3f a1 [2] 11 83 [2] 05 98 [2] 0a 82 [2] 14 9f [2] 16 9e [2] 0d 98 [2] 11 9f [2] 0d b0 }

  condition:
    any of them
}