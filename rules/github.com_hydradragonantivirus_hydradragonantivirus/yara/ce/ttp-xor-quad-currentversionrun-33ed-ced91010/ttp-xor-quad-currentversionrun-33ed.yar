rule TTP_XOR_QUAD_CurrentVersionRun_33ed {
  strings:
    $key_33ed = { 60 82 [2] 44 8c [2] 6f a0 [2] 41 82 [2] 55 99 [2] 5a 83 [2] 44 9e [2] 46 9f [2] 5d 99 [2] 41 9e [2] 5d b1 }

  condition:
    any of them
}