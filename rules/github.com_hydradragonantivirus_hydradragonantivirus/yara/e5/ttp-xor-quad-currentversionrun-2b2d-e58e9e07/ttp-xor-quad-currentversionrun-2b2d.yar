rule TTP_XOR_QUAD_CurrentVersionRun_2b2d {
  strings:
    $key_2b2d = { 78 42 [2] 5c 4c [2] 77 60 [2] 59 42 [2] 4d 59 [2] 42 43 [2] 5c 5e [2] 5e 5f [2] 45 59 [2] 59 5e [2] 45 71 }

  condition:
    any of them
}