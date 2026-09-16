rule TTP_XOR_QUAD_CurrentVersionRun_083a {
  strings:
    $key_083a = { 5b 55 [2] 7f 5b [2] 54 77 [2] 7a 55 [2] 6e 4e [2] 61 54 [2] 7f 49 [2] 7d 48 [2] 66 4e [2] 7a 49 [2] 66 66 }

  condition:
    any of them
}