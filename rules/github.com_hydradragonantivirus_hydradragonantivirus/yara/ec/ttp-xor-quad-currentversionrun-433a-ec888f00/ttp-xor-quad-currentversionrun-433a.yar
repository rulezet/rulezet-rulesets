rule TTP_XOR_QUAD_CurrentVersionRun_433a {
  strings:
    $key_433a = { 10 55 [2] 34 5b [2] 1f 77 [2] 31 55 [2] 25 4e [2] 2a 54 [2] 34 49 [2] 36 48 [2] 2d 4e [2] 31 49 [2] 2d 66 }

  condition:
    any of them
}