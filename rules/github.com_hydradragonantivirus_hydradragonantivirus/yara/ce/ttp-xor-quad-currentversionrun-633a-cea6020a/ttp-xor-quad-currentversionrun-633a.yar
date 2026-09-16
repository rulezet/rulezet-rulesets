rule TTP_XOR_QUAD_CurrentVersionRun_633a {
  strings:
    $key_633a = { 30 55 [2] 14 5b [2] 3f 77 [2] 11 55 [2] 05 4e [2] 0a 54 [2] 14 49 [2] 16 48 [2] 0d 4e [2] 11 49 [2] 0d 66 }

  condition:
    any of them
}