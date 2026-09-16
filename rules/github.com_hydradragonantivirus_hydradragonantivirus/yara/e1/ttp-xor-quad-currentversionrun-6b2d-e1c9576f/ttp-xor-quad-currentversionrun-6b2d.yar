rule TTP_XOR_QUAD_CurrentVersionRun_6b2d {
  strings:
    $key_6b2d = { 38 42 [2] 1c 4c [2] 37 60 [2] 19 42 [2] 0d 59 [2] 02 43 [2] 1c 5e [2] 1e 5f [2] 05 59 [2] 19 5e [2] 05 71 }

  condition:
    any of them
}