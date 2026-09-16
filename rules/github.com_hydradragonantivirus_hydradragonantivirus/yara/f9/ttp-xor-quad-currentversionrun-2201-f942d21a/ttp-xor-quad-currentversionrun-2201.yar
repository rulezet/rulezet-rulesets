rule TTP_XOR_QUAD_CurrentVersionRun_2201 {
  strings:
    $key_2201 = { 71 6e [2] 55 60 [2] 7e 4c [2] 50 6e [2] 44 75 [2] 4b 6f [2] 55 72 [2] 57 73 [2] 4c 75 [2] 50 72 [2] 4c 5d }

  condition:
    any of them
}