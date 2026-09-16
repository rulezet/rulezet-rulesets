rule TTP_XOR_QUAD_CurrentVersionRun_197a {
  strings:
    $key_197a = { 4a 15 [2] 6e 1b [2] 45 37 [2] 6b 15 [2] 7f 0e [2] 70 14 [2] 6e 09 [2] 6c 08 [2] 77 0e [2] 6b 09 [2] 77 26 }

  condition:
    any of them
}