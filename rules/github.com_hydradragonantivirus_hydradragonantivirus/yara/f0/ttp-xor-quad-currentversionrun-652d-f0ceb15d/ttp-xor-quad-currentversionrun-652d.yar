rule TTP_XOR_QUAD_CurrentVersionRun_652d {
  strings:
    $key_652d = { 36 42 [2] 12 4c [2] 39 60 [2] 17 42 [2] 03 59 [2] 0c 43 [2] 12 5e [2] 10 5f [2] 0b 59 [2] 17 5e [2] 0b 71 }

  condition:
    any of them
}