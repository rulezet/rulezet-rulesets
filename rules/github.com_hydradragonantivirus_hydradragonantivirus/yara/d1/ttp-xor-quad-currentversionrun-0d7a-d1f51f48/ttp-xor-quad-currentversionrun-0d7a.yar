rule TTP_XOR_QUAD_CurrentVersionRun_0d7a {
  strings:
    $key_0d7a = { 5e 15 [2] 7a 1b [2] 51 37 [2] 7f 15 [2] 6b 0e [2] 64 14 [2] 7a 09 [2] 78 08 [2] 63 0e [2] 7f 09 [2] 63 26 }

  condition:
    any of them
}