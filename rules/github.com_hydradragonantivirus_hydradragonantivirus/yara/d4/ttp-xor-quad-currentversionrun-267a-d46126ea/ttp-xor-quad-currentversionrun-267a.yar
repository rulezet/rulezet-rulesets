rule TTP_XOR_QUAD_CurrentVersionRun_267a {
  strings:
    $key_267a = { 75 15 [2] 51 1b [2] 7a 37 [2] 54 15 [2] 40 0e [2] 4f 14 [2] 51 09 [2] 53 08 [2] 48 0e [2] 54 09 [2] 48 26 }

  condition:
    any of them
}