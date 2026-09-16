rule TTP_XOR_QUAD_CurrentVersionRun_097a {
  strings:
    $key_097a = { 5a 15 [2] 7e 1b [2] 55 37 [2] 7b 15 [2] 6f 0e [2] 60 14 [2] 7e 09 [2] 7c 08 [2] 67 0e [2] 7b 09 [2] 67 26 }

  condition:
    any of them
}