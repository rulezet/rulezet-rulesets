rule TTP_XOR_QUAD_CurrentVersionRun_663a {
  strings:
    $key_663a = { 35 55 [2] 11 5b [2] 3a 77 [2] 14 55 [2] 00 4e [2] 0f 54 [2] 11 49 [2] 13 48 [2] 08 4e [2] 14 49 [2] 08 66 }

  condition:
    any of them
}