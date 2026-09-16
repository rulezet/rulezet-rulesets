rule TTP_XOR_QUAD_CurrentVersionRun_712d {
  strings:
    $key_712d = { 22 42 [2] 06 4c [2] 2d 60 [2] 03 42 [2] 17 59 [2] 18 43 [2] 06 5e [2] 04 5f [2] 1f 59 [2] 03 5e [2] 1f 71 }

  condition:
    any of them
}