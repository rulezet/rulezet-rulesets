rule TTP_XOR_QUAD_CurrentVersionRun_471c {
  strings:
    $key_471c = { 14 73 [2] 30 7d [2] 1b 51 [2] 35 73 [2] 21 68 [2] 2e 72 [2] 30 6f [2] 32 6e [2] 29 68 [2] 35 6f [2] 29 40 }

  condition:
    any of them
}