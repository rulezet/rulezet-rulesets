rule TTP_XOR_QUAD_CurrentVersionRun_433d {
  strings:
    $key_433d = { 10 52 [2] 34 5c [2] 1f 70 [2] 31 52 [2] 25 49 [2] 2a 53 [2] 34 4e [2] 36 4f [2] 2d 49 [2] 31 4e [2] 2d 61 }

  condition:
    any of them
}