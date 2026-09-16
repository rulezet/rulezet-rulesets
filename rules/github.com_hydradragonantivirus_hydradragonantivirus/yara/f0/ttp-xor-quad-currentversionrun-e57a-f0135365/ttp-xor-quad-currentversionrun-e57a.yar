rule TTP_XOR_QUAD_CurrentVersionRun_e57a {
  strings:
    $key_e57a = { b6 15 [2] 92 1b [2] b9 37 [2] 97 15 [2] 83 0e [2] 8c 14 [2] 92 09 [2] 90 08 [2] 8b 0e [2] 97 09 [2] 8b 26 }

  condition:
    any of them
}