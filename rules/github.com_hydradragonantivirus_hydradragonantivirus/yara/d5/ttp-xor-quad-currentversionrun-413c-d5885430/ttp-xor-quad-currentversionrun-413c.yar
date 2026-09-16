rule TTP_XOR_QUAD_CurrentVersionRun_413c {
  strings:
    $key_413c = { 12 53 [2] 36 5d [2] 1d 71 [2] 33 53 [2] 27 48 [2] 28 52 [2] 36 4f [2] 34 4e [2] 2f 48 [2] 33 4f [2] 2f 60 }

  condition:
    any of them
}