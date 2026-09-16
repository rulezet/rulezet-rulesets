rule TTP_XOR_QUAD_CurrentVersionRun_251c {
  strings:
    $key_251c = { 76 73 [2] 52 7d [2] 79 51 [2] 57 73 [2] 43 68 [2] 4c 72 [2] 52 6f [2] 50 6e [2] 4b 68 [2] 57 6f [2] 4b 40 }

  condition:
    any of them
}