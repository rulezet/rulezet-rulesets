rule TTP_XOR_QUAD_CurrentVersionRun_692d {
  strings:
    $key_692d = { 3a 42 [2] 1e 4c [2] 35 60 [2] 1b 42 [2] 0f 59 [2] 00 43 [2] 1e 5e [2] 1c 5f [2] 07 59 [2] 1b 5e [2] 07 71 }

  condition:
    any of them
}