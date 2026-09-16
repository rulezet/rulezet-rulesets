rule TTP_XOR_QUAD_CurrentVersionRun_3b2d {
  strings:
    $key_3b2d = { 68 42 [2] 4c 4c [2] 67 60 [2] 49 42 [2] 5d 59 [2] 52 43 [2] 4c 5e [2] 4e 5f [2] 55 59 [2] 49 5e [2] 55 71 }

  condition:
    any of them
}