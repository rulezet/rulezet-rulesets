rule TTP_XOR_QUAD_CurrentVersionRun_7833 {
  strings:
    $key_7833 = { 2b 5c [2] 0f 52 [2] 24 7e [2] 0a 5c [2] 1e 47 [2] 11 5d [2] 0f 40 [2] 0d 41 [2] 16 47 [2] 0a 40 [2] 16 6f }

  condition:
    any of them
}