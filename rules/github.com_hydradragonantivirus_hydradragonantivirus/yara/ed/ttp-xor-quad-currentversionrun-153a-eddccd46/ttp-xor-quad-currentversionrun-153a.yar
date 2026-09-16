rule TTP_XOR_QUAD_CurrentVersionRun_153a {
  strings:
    $key_153a = { 46 55 [2] 62 5b [2] 49 77 [2] 67 55 [2] 73 4e [2] 7c 54 [2] 62 49 [2] 60 48 [2] 7b 4e [2] 67 49 [2] 7b 66 }

  condition:
    any of them
}