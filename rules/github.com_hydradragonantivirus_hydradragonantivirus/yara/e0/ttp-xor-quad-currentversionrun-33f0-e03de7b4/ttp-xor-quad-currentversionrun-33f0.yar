rule TTP_XOR_QUAD_CurrentVersionRun_33f0 {
  strings:
    $key_33f0 = { 60 9f [2] 44 91 [2] 6f bd [2] 41 9f [2] 55 84 [2] 5a 9e [2] 44 83 [2] 46 82 [2] 5d 84 [2] 41 83 [2] 5d ac }

  condition:
    any of them
}