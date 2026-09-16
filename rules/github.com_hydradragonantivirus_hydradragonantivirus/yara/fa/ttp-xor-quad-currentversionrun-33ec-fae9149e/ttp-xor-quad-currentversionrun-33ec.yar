rule TTP_XOR_QUAD_CurrentVersionRun_33ec {
  strings:
    $key_33ec = { 60 83 [2] 44 8d [2] 6f a1 [2] 41 83 [2] 55 98 [2] 5a 82 [2] 44 9f [2] 46 9e [2] 5d 98 [2] 41 9f [2] 5d b0 }

  condition:
    any of them
}