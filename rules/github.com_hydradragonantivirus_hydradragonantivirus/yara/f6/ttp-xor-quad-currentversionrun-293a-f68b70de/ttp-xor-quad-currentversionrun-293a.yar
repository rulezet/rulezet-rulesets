rule TTP_XOR_QUAD_CurrentVersionRun_293a {
  strings:
    $key_293a = { 7a 55 [2] 5e 5b [2] 75 77 [2] 5b 55 [2] 4f 4e [2] 40 54 [2] 5e 49 [2] 5c 48 [2] 47 4e [2] 5b 49 [2] 47 66 }

  condition:
    any of them
}