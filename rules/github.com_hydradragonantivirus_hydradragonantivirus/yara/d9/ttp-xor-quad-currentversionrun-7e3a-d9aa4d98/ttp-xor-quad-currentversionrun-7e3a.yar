rule TTP_XOR_QUAD_CurrentVersionRun_7e3a {
  strings:
    $key_7e3a = { 2d 55 [2] 09 5b [2] 22 77 [2] 0c 55 [2] 18 4e [2] 17 54 [2] 09 49 [2] 0b 48 [2] 10 4e [2] 0c 49 [2] 10 66 }

  condition:
    any of them
}