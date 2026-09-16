rule TTP_XOR_QUAD_CurrentVersionRun_7301 {
  strings:
    $key_7301 = { 20 6e [2] 04 60 [2] 2f 4c [2] 01 6e [2] 15 75 [2] 1a 6f [2] 04 72 [2] 06 73 [2] 1d 75 [2] 01 72 [2] 1d 5d }

  condition:
    any of them
}