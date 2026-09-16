rule TTP_XOR_QUAD_CurrentVersionRun_7901 {
  strings:
    $key_7901 = { 2a 6e [2] 0e 60 [2] 25 4c [2] 0b 6e [2] 1f 75 [2] 10 6f [2] 0e 72 [2] 0c 73 [2] 17 75 [2] 0b 72 [2] 17 5d }

  condition:
    any of them
}