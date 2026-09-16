rule TTP_XOR_QUAD_CurrentVersionRun_273a {
  strings:
    $key_273a = { 74 55 [2] 50 5b [2] 7b 77 [2] 55 55 [2] 41 4e [2] 4e 54 [2] 50 49 [2] 52 48 [2] 49 4e [2] 55 49 [2] 49 66 }

  condition:
    any of them
}