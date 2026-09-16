rule TTP_XOR_QUAD_CurrentVersionRun_470d {
  strings:
    $key_470d = { 14 62 [2] 30 6c [2] 1b 40 [2] 35 62 [2] 21 79 [2] 2e 63 [2] 30 7e [2] 32 7f [2] 29 79 [2] 35 7e [2] 29 51 }

  condition:
    any of them
}