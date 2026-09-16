rule TTP_XOR_QUAD_CurrentVersionRun_4e3c {
  strings:
    $key_4e3c = { 1d 53 [2] 39 5d [2] 12 71 [2] 3c 53 [2] 28 48 [2] 27 52 [2] 39 4f [2] 3b 4e [2] 20 48 [2] 3c 4f [2] 20 60 }

  condition:
    any of them
}