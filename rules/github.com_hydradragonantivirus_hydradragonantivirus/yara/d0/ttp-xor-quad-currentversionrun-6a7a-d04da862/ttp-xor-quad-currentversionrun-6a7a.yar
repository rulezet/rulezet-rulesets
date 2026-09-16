rule TTP_XOR_QUAD_CurrentVersionRun_6a7a {
  strings:
    $key_6a7a = { 39 15 [2] 1d 1b [2] 36 37 [2] 18 15 [2] 0c 0e [2] 03 14 [2] 1d 09 [2] 1f 08 [2] 04 0e [2] 18 09 [2] 04 26 }

  condition:
    any of them
}