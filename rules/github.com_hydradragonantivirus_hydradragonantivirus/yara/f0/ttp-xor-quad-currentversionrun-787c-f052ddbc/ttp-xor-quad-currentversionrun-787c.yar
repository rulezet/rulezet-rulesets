rule TTP_XOR_QUAD_CurrentVersionRun_787c {
  strings:
    $key_787c = { 2b 13 [2] 0f 1d [2] 24 31 [2] 0a 13 [2] 1e 08 [2] 11 12 [2] 0f 0f [2] 0d 0e [2] 16 08 [2] 0a 0f [2] 16 20 }

  condition:
    any of them
}