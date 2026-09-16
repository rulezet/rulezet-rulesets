rule TTP_XOR_QUAD_CurrentVersionRun_767a {
  strings:
    $key_767a = { 25 15 [2] 01 1b [2] 2a 37 [2] 04 15 [2] 10 0e [2] 1f 14 [2] 01 09 [2] 03 08 [2] 18 0e [2] 04 09 [2] 18 26 }

  condition:
    any of them
}