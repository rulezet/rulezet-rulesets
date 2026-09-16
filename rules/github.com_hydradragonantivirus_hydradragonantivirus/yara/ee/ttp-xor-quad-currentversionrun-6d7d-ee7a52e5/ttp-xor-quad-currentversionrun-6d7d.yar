rule TTP_XOR_QUAD_CurrentVersionRun_6d7d {
  strings:
    $key_6d7d = { 3e 12 [2] 1a 1c [2] 31 30 [2] 1f 12 [2] 0b 09 [2] 04 13 [2] 1a 0e [2] 18 0f [2] 03 09 [2] 1f 0e [2] 03 21 }

  condition:
    any of them
}