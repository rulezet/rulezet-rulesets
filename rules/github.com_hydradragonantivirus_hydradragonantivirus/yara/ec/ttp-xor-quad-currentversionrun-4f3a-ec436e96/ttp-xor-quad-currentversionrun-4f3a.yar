rule TTP_XOR_QUAD_CurrentVersionRun_4f3a {
  strings:
    $key_4f3a = { 1c 55 [2] 38 5b [2] 13 77 [2] 3d 55 [2] 29 4e [2] 26 54 [2] 38 49 [2] 3a 48 [2] 21 4e [2] 3d 49 [2] 21 66 }

  condition:
    any of them
}