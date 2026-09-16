rule TTP_XOR_QUAD_CurrentVersionRun_167a {
  strings:
    $key_167a = { 45 15 [2] 61 1b [2] 4a 37 [2] 64 15 [2] 70 0e [2] 7f 14 [2] 61 09 [2] 63 08 [2] 78 0e [2] 64 09 [2] 78 26 }

  condition:
    any of them
}