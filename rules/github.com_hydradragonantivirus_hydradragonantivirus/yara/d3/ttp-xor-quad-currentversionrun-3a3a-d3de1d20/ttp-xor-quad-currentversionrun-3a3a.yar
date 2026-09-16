rule TTP_XOR_QUAD_CurrentVersionRun_3a3a {
  strings:
    $key_3a3a = { 69 55 [2] 4d 5b [2] 66 77 [2] 48 55 [2] 5c 4e [2] 53 54 [2] 4d 49 [2] 4f 48 [2] 54 4e [2] 48 49 [2] 54 66 }

  condition:
    any of them
}