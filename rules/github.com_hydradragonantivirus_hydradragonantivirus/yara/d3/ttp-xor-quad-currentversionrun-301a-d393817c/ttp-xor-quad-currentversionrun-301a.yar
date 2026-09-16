rule TTP_XOR_QUAD_CurrentVersionRun_301a {
  strings:
    $key_301a = { 63 75 [2] 47 7b [2] 6c 57 [2] 42 75 [2] 56 6e [2] 59 74 [2] 47 69 [2] 45 68 [2] 5e 6e [2] 42 69 [2] 5e 46 }

  condition:
    any of them
}