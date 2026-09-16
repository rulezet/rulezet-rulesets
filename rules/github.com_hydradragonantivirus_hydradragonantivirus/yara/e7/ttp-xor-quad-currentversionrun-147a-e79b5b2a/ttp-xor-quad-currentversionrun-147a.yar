rule TTP_XOR_QUAD_CurrentVersionRun_147a {
  strings:
    $key_147a = { 47 15 [2] 63 1b [2] 48 37 [2] 66 15 [2] 72 0e [2] 7d 14 [2] 63 09 [2] 61 08 [2] 7a 0e [2] 66 09 [2] 7a 26 }

  condition:
    any of them
}