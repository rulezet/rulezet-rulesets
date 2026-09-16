rule TTP_XOR_QUAD_CurrentVersionRun_750c {
  strings:
    $key_750c = { 26 63 [2] 02 6d [2] 29 41 [2] 07 63 [2] 13 78 [2] 1c 62 [2] 02 7f [2] 00 7e [2] 1b 78 [2] 07 7f [2] 1b 50 }

  condition:
    any of them
}