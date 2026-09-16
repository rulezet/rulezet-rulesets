rule TTP_XOR_QUAD_CurrentVersionRun_471d {
  strings:
    $key_471d = { 14 72 [2] 30 7c [2] 1b 50 [2] 35 72 [2] 21 69 [2] 2e 73 [2] 30 6e [2] 32 6f [2] 29 69 [2] 35 6e [2] 29 41 }

  condition:
    any of them
}