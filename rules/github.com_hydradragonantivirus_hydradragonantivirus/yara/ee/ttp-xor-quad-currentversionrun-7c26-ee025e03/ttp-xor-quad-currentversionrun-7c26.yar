rule TTP_XOR_QUAD_CurrentVersionRun_7c26 {
  strings:
    $key_7c26 = { 2f 49 [2] 0b 47 [2] 20 6b [2] 0e 49 [2] 1a 52 [2] 15 48 [2] 0b 55 [2] 09 54 [2] 12 52 [2] 0e 55 [2] 12 7a }

  condition:
    any of them
}