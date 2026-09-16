rule TTP_XOR_QUAD_CurrentVersionRun_762d {
  strings:
    $key_762d = { 25 42 [2] 01 4c [2] 2a 60 [2] 04 42 [2] 10 59 [2] 1f 43 [2] 01 5e [2] 03 5f [2] 18 59 [2] 04 5e [2] 18 71 }

  condition:
    any of them
}