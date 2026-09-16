rule TTP_XOR_QUAD_CurrentVersionRun_6d4a {
  strings:
    $key_6d4a = { 3e 25 [2] 1a 2b [2] 31 07 [2] 1f 25 [2] 0b 3e [2] 04 24 [2] 1a 39 [2] 18 38 [2] 03 3e [2] 1f 39 [2] 03 16 }

  condition:
    any of them
}