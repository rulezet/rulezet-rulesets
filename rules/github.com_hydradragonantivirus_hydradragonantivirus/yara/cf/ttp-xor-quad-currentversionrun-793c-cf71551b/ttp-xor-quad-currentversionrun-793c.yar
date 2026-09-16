rule TTP_XOR_QUAD_CurrentVersionRun_793c {
  strings:
    $key_793c = { 2a 53 [2] 0e 5d [2] 25 71 [2] 0b 53 [2] 1f 48 [2] 10 52 [2] 0e 4f [2] 0c 4e [2] 17 48 [2] 0b 4f [2] 17 60 }

  condition:
    any of them
}