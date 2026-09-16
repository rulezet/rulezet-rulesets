rule TTP_XOR_QUAD_CurrentVersionRun_7c3c {
  strings:
    $key_7c3c = { 2f 53 [2] 0b 5d [2] 20 71 [2] 0e 53 [2] 1a 48 [2] 15 52 [2] 0b 4f [2] 09 4e [2] 12 48 [2] 0e 4f [2] 12 60 }

  condition:
    any of them
}