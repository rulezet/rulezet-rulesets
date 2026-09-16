rule TTP_XOR_QUAD_CurrentVersionRun_3333 {
  strings:
    $key_3333 = { 60 5c [2] 44 52 [2] 6f 7e [2] 41 5c [2] 55 47 [2] 5a 5d [2] 44 40 [2] 46 41 [2] 5d 47 [2] 41 40 [2] 5d 6f }

  condition:
    any of them
}