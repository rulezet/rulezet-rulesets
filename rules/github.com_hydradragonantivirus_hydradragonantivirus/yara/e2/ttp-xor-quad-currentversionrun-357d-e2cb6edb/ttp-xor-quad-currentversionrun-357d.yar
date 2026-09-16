rule TTP_XOR_QUAD_CurrentVersionRun_357d {
  strings:
    $key_357d = { 66 12 [2] 42 1c [2] 69 30 [2] 47 12 [2] 53 09 [2] 5c 13 [2] 42 0e [2] 40 0f [2] 5b 09 [2] 47 0e [2] 5b 21 }

  condition:
    any of them
}