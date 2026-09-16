rule TTP_XOR_QUAD_CurrentVersionRun_603c {
  strings:
    $key_603c = { 33 53 [2] 17 5d [2] 3c 71 [2] 12 53 [2] 06 48 [2] 09 52 [2] 17 4f [2] 15 4e [2] 0e 48 [2] 12 4f [2] 0e 60 }

  condition:
    any of them
}