rule TTP_XOR_QUAD_CurrentVersionRun_443c {
  strings:
    $key_443c = { 17 53 [2] 33 5d [2] 18 71 [2] 36 53 [2] 22 48 [2] 2d 52 [2] 33 4f [2] 31 4e [2] 2a 48 [2] 36 4f [2] 2a 60 }

  condition:
    any of them
}