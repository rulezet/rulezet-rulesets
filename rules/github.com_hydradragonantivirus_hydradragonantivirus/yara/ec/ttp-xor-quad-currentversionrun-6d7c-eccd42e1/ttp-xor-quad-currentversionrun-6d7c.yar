rule TTP_XOR_QUAD_CurrentVersionRun_6d7c {
  strings:
    $key_6d7c = { 3e 13 [2] 1a 1d [2] 31 31 [2] 1f 13 [2] 0b 08 [2] 04 12 [2] 1a 0f [2] 18 0e [2] 03 08 [2] 1f 0f [2] 03 20 }

  condition:
    any of them
}