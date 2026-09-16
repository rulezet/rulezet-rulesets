rule TTP_XOR_QUAD_CurrentVersionRun_5a3c {
  strings:
    $key_5a3c = { 09 53 [2] 2d 5d [2] 06 71 [2] 28 53 [2] 3c 48 [2] 33 52 [2] 2d 4f [2] 2f 4e [2] 34 48 [2] 28 4f [2] 34 60 }

  condition:
    any of them
}