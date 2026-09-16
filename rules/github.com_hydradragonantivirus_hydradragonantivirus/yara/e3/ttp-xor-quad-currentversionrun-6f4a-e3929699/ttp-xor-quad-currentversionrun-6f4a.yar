rule TTP_XOR_QUAD_CurrentVersionRun_6f4a {
  strings:
    $key_6f4a = { 3c 25 [2] 18 2b [2] 33 07 [2] 1d 25 [2] 09 3e [2] 06 24 [2] 18 39 [2] 1a 38 [2] 01 3e [2] 1d 39 [2] 01 16 }

  condition:
    any of them
}