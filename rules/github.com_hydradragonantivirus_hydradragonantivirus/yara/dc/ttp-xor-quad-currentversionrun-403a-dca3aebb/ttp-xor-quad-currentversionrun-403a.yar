rule TTP_XOR_QUAD_CurrentVersionRun_403a {
  strings:
    $key_403a = { 13 55 [2] 37 5b [2] 1c 77 [2] 32 55 [2] 26 4e [2] 29 54 [2] 37 49 [2] 35 48 [2] 2e 4e [2] 32 49 [2] 2e 66 }

  condition:
    any of them
}