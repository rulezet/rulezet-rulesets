rule TTP_XOR_QUAD_CurrentVersionRun_473d {
  strings:
    $key_473d = { 14 52 [2] 30 5c [2] 1b 70 [2] 35 52 [2] 21 49 [2] 2e 53 [2] 30 4e [2] 32 4f [2] 29 49 [2] 35 4e [2] 29 61 }

  condition:
    any of them
}