rule TTP_XOR_QUAD_CurrentVersionRun_477d {
  strings:
    $key_477d = { 14 12 [2] 30 1c [2] 1b 30 [2] 35 12 [2] 21 09 [2] 2e 13 [2] 30 0e [2] 32 0f [2] 29 09 [2] 35 0e [2] 29 21 }

  condition:
    any of them
}